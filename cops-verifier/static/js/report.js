/**
 * Handles the file submission. Changes the visibility and state of
 * the result div ("passed" vs. "failed" indicator).
 * 
 * @param {Event} event DOM 'submit' event
 */
const handleReportSubmit = (event) => {
    event.preventDefault()

    // reset validation status tag
    const status = document.getElementById('validation-result')
    status.style.display = 'none'
    status.innerText = ''

    // display spinner
    const loader = document.getElementById('validation-wait')
    loader.classList.toggle('hide', false)

    // form and data
    const form = event.currentTarget
    const url = new URL(form.action)
    const formData = new FormData(form)

    const options = {
        method: form.method,
        body: formData
    }

    fetch(url, options)
        .then(res => {
            if (!res.ok)
                return Promise.reject(res)

            console.dir(res)
            status.style.display = 'initial'
            status.innerText = 'Validation Successful.'
        })
        .catch(err => {
            console.dir(err)
            status.style.display = 'initial'
            status.innerText = 'Validation Failed.'
        })
        .finally(() => {
            form.reset()
            loader.classList.toggle('hide', true)
            // form reset does not emit select change event
            document.getElementById('provider')
                .dispatchEvent(new Event('change'))
        })
}

/**
 * Handles provider select change, toggling state and visibility of
 * additional required fields.
 * 
 * @param {Event} event DOM 'change' event
 */
const handleProviderChange = (event) => {
    const enableFieldsetById = (id) => {
        fieldset = document.getElementById(id)
        fieldset.classList.toggle('hide', false)
        fieldset.toggleAttribute('disabled', false)
    }

    const disableFieldsetById = (id) => {
        fieldset = document.getElementById(id)
        fieldset.classList.toggle('hide', true)
        fieldset.toggleAttribute('disabled', true)
    }

    switch (event.currentTarget.value) {
        case 'OVH':
            enableFieldsetById('ovh-files')
            disableFieldsetById('aws-files')
            break
        case 'AWS':
            disableFieldsetById('ovh-files')
            enableFieldsetById('aws-files')
            break
        case 'AZURE':
        default:
            disableFieldsetById('ovh-files')
            disableFieldsetById('aws-files')
    }
}

/**
 * Initializes on window load.
 * 
 * @param {Event} event DOM 'load' event
 */
const  init = (event) => {
    // add provider change handler (does _not_ fire on reset!)
    const providerSelect = document.getElementById('provider')
    providerSelect.addEventListener('change', handleProviderChange)
    // trigger change event on load
    providerSelect.dispatchEvent(new Event('change'))

    // add form submission handler
    const reportForm = document.getElementById('report-form')
    reportForm.addEventListener('submit', handleReportSubmit)
}

// Entry point
window.onload = init
