import $ from 'jquery';
import firebaseConfig from "./firebaseConfig";
import { FirebaseApp, initializeApp } from "firebase/app";
import { Auth, getAuth, onAuthStateChanged, signInWithEmailAndPassword, signOut } from "firebase/auth";
import { toast } from "react-toastify";

const app: FirebaseApp = initializeApp(firebaseConfig);
const auth: Auth = getAuth(app);

// Endereço da API. No Docker o build usa VITE_API_URL=/api (mesma origem,
// via Nginx). Sem a variável, usa o backend local de desenvolvimento.
export const API_URL: string = import.meta.env.VITE_API_URL ?? "http://127.0.0.1:5000";


async function createUser (email: string, password: string) {
  const response = await fetch(`${API_URL}/users/create`, {
    method: 'POST',
    mode: "cors",
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({email, password})
  });
  const json = await response.json();
  if (!response.ok) throw new Error(json.error || "Could not create user");
  return json;
}


function performSignup() {
  const email: string = String($("#signup-email-input").val() ?? "");
  const password: string = String($("#signup-password-input").val() ?? "");

  createUser(email, password)
    .then(() => {
      return signInWithEmailAndPassword(auth, email, password)
        .then(() => {
          window.location.replace("/");
        });
    })
    .catch((e) => {
      toast.error(`Sign up failed: ${e.message || e}`, {
        position: "top-right",
        hideProgressBar: true,
        closeOnClick: true,   
        pauseOnHover: true,
        draggable: true,
        progress: undefined,
        theme: "light"
      });
    });
};

/**
 * This function performs the user login transaction with firebase.
 * 
 */
function performLogin() {
  const email: string = String($("#login-email-input").val() ?? "");
  const password: string = String($("#login-password-input").val() ?? "");
  signInWithEmailAndPassword(auth, email, password)
    .then(() => {
      window.location.replace("/");
    })
    .catch((e) => {
      toast.error(`Login failed: ${e.message}`);
    });
}



/**
 * This function sets the profile information if the user is logged in.
 * 
 * @param setMajors 
 * @param setMinors 
 * @param setYear 
 * @param setCollege 
 * @param setCourses 
 */
async function setProfileInfoIfLoggedIn(
  setMajors: Function,
  setMinors: Function,
  setYear: Function,
  setCollege: Function,
  setCourses: Function,
  setAbout: Function
){
  onAuthStateChanged(auth, async (user) => {
    if (!ensureUserLoggedIn()) return;
    const idToken = await user?.getIdToken()

    try {
      // O token vai somente no header Authorization, nunca na URL.
      const response = await fetch(`${API_URL}/users/info`, {
        method: "GET",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${idToken}`
        }
      })

      const data = await response.json()
      if (!data || data.error) return  // usuário novo, ainda sem perfil salvo

      if (data["majors"]) {
        setMajors(data["majors"])
      }

      if (data["minors"]) {
        setMinors(data["minors"])
      }

      if (data["year"]) {
        //$("#year-output").val(data["year"])
        setYear(data["year"])
      }

      if (data["college"]) {
        //$("#college-output").val(data["college"])
        setCollege(data["college"])
      }

      if (data["courses"]) {
        setCourses(data["courses"])
      }

      if (data["about"]) {
        $("#info-output").val(data["about"])
        setAbout(data["about"])
      }

    }
    catch (e) {
      toast.error(`Failed to fetch data: ${e}`)
    }
})
}

/**
 * This function saves any profile changes that occurs on the user dashboard. 
 * 
 * @param majors 
 * @param minors 
 * @param courses 
 * @returns 
 */
async function saveProfileChanges (majors: string[], minors: string[], courses: string[]) {
  if (!ensureUserLoggedIn()) return;
  const user = auth.currentUser;
  const about = $("#info-output").val()
  const year = $("#year-output").val()
  const college = $("#college-output").val()
  const idToken = await user?.getIdToken(); // User won't be null due to the early return statement above, ignore the ?. 

  const data = {
    majors: majors,
    minors: minors,
    year: year,
    college: college,
    courses: courses,
    about: about
  };

  fetch(`${API_URL}/users/info`, {
    method: "POST",
    headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${idToken}`
    },
    body: JSON.stringify(data)
  })
  .then(async (res) => {
    if (!res.ok) throw new Error((await res.json()).error || res.statusText);
    toast.success("Successfully saved your information!");
  })
  .catch((e: Error) => {
    toast.error(`Failed to save your information: ${e}`);
  });
}


/**
 * This functions sends the query, as well as the user id (if the user is logged in) to the backend and returns the response. 
 * 
 * @param query 
 * @returns 
 */
async function fetchCourseSphereResponse(query: string) {
  const user = auth.currentUser;
  const idToken = user ? await user.getIdToken() : undefined;
  const data = { query };
  const response = await fetch(`${API_URL}/users/query`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(idToken ? { 'Authorization': `Bearer ${idToken}` } : {})
    },
    body: JSON.stringify(data)
  })
  .then(response => response.json())
  .then(result => {
    toast.success("Successfully retrieved bot response!");
    return {
      botResponse: result.botResponse,
      newRecommendations: result.newRecommendations || []
    };
  })
  .catch((error: Error) => {
    console.error("Failed to fetch bot response:", error);
    toast.error(`Failed to fetch bot response: ${error.message}`);
    return {
      botResponse: `Failed to get bot response, most likely an Unsupported Query: echo "${query}", This is testing, in the future, it will simply return: "Unsupported Query"`,
      newRecommendations: []
    };
  });
  return response;
}

/**
 * Logout completo: pede ao backend para revogar os tokens do usuário
 * (assim um token copiado deixa de valer) e depois encerra a sessão local.
 */
async function performLogout() {
  const user = auth.currentUser;
  try {
    if (user) {
      const idToken = await user.getIdToken();
      await fetch(`${API_URL}/auth/logout`, {
        method: "POST",
        headers: { "Authorization": `Bearer ${idToken}` }
      });
    }
  } catch (e) {
    console.error("Failed to revoke session on the server:", e);
  } finally {
    await signOut(auth);
    window.location.replace("/");
  }
}

function ensureUserLoggedIn(): boolean {
  const user = auth.currentUser;
  if (user == null) {
    alert("Not logged in");
    return false;
  }
  return true;
}


async function saveCourseSphereChat(chatId: string, messages: Message[]) {
  if (!await ensureUserLoggedIn()) return;
  
  const user = auth.currentUser;
  const idToken = await user?.getIdToken();

  const response = await fetch(`${API_URL}/chats/${chatId}/messages`, {
    method: 'POST',
    keepalive: true,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${idToken}`
    },
    body: JSON.stringify({
      messages: messages.map(message => ({
        sender: message.sender,
        content: message.content,
        messageID: message.messageID,
        timestamp: message.timestamp
      }))
    })
  });
  
  const data = await response.json();
  if (!response.ok) {
    alert(data.error || 'Error saving messages');
  }
}





async function updateCourseSphereChat(chatId: string, messageId: string, updatedContent: string) {
  if (!await ensureUserLoggedIn()) return;
  const user = auth.currentUser;
  const idToken = await user?.getIdToken();

  const response = await fetch(`${API_URL}/chats/${chatId}/messages/${messageId}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${idToken}`
    },
    body: JSON.stringify({
      content: updatedContent
    })
  });
  
  const data = await response.json();
  if (!response.ok) {
    alert(data.error);
  }
}

async function deleteCourseSphereChat(chatId: string, messageId: string) {
  if (!await ensureUserLoggedIn()) return;
  const user = auth.currentUser;
  const idToken = await user?.getIdToken();

  const response = await fetch(`${API_URL}/chats/${chatId}/messages/${messageId}`, {
    method: 'DELETE',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${idToken}`
    }
  });
  
  const data = await response.json();
  if (!response.ok) {
    alert(data.error);
  }
}

// h Function
async function h(data: any): Promise<string | undefined> {
  if (!await ensureUserLoggedIn()) return;

  const user = auth.currentUser;
  const idToken = await user?.getIdToken();

  const response = await fetch(`${API_URL}/hash`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${idToken}`  
    },
    body: JSON.stringify(data)  
  });

  if (!response.ok) {
    throw new Error(`Error generating message ID: ${response.statusText}`);
  }

  const result = await response.json();
  return result.messageID;
}


export {
  createUser,
  performSignup,
  performLogin,
  performLogout,
  saveProfileChanges,
  setProfileInfoIfLoggedIn,
  fetchCourseSphereResponse,
  saveCourseSphereChat,
  updateCourseSphereChat,
  deleteCourseSphereChat,
  h
};
