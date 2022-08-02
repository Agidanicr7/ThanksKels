const Signup = async () =>{
    
    try { 
        const Details = {}
        Details.username = document.getElementById("username").value
        Details.firstname = document.getElementById("firstname").value
        Details.email = document.getElementById("email").value
        Details.lastname = document.getElementById("lastname").value
        Details.password = document.getElementById("password").value
      
        console.log("details",Details);

        var arrow = document.getElementById("arrow")
        var spin = document.getElementById("spin")
        arrow.style.display = "none"
        spin.style.display = "block"


        const resp = await  axios.post('/signup', Details,{
            headers:{
                'Content-Type': 'application/json'
            }
            
        });
        
        //  console.log(resp.data);
        if (resp.data.status==200) {
            var notify = document.getElementById("notification")
            document.getElementById('alertmsg').innerText = resp.data.msg
            notify.style.display = "block"
            arrow.style.display = "block"
            spin.style.display = "none"
            window.location.replace("/dashboard")
            console.log(resp);
        }

        if(resp.data.status==404){
            var notify = document.getElementById("notification")
            document.getElementById("alertmsg").innerText = resp.data.msg
            notify.classList.remove("is-primary")
            notify.classList.add("is-danger")
            notify.style.display = "block"
            arrow.style.display = "block"
            spin.style.display = "none"
        }

    } catch (error) {
      console.log(error)
    }


  }


  const Signin = async () =>{

    try { 
        const Details = {}
        Details.username = document.getElementById("username").value
        Details.password = document.getElementById("password").value
        var arrow = document.getElementById("arrow")
        var spin = document.getElementById("spin")
        arrow.style.display = "none"
        spin.style.display = "block"


        const resp = await  axios.post('/signin', Details,{
            headers:{
                'Content-Type': 'application/json'
            }
            
        });
        
        //  console.log(resp.data);
        if (resp.data.status==200) {
            var notify = document.getElementById("notification")
            document.getElementById('alertmsg').innerText = resp.data.msg
            notify.style.display = "block"
            arrow.style.display = "block"
            spin.style.display = "none"
            console.log(resp);
            window.location.replace("/dashboard")
        }

        if(resp.data.status==404){
            var notify = document.getElementById("notification")
            document.getElementById("alertmsg").innerText = resp.data.msg
            notify.classList.remove("is-primary")
            notify.classList.add("is-danger")
            notify.style.display = "block"
            arrow.style.display = "block"
            spin.style.display = "none"
        }

    } catch (error) {
      console.log(error)
    }


  }

