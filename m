Return-Path: <kasan-dev+bncBC7OBJGL2MHBBU4PXXWQKGQEDJWGFEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id C128BE0B4E
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2019 20:17:56 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id i25sf11575960qtm.17
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2019 11:17:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571768275; cv=pass;
        d=google.com; s=arc-20160816;
        b=pYd35WfTlHzvru83XiUmkMNIJ709s4G9GJBC3PPOwoEnBozY7s0jf8YPYMXRDogbVM
         n9RF204oXldxRHV1hd9tW9yR5Bz943/B1MZJ+T9szdFa/9keqL3lSlMip2CNv9fUSWUA
         c9g4R4nAjdu6D0a0N9kMMSzjTSZjiOovSIgFxOppbCeFl+ocD3p0WAgea0HDv+qiYdha
         pUyoSMDEQwkGYwhK/loMSs8MlzdiFEqz5dr2zhScu5TJikcF4ct5YV0YqvY61F1tiiHp
         puHMRQyxFER23FBQLYOmzg/0bvmzGUlci8ciPu+Vyj3G/odQOHZLfWL3r1XQ9hoaPftQ
         H/Wg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=cmpujzszQP2cKWC/veQBh8FhwtXTRZeeduWO0N0awRQ=;
        b=a9S2yD9fcepbN+pED2aHBlG469nl+N8S4qBMfNAfZKW4eISstLLPstMC+rY5b94ltL
         oX6yP+cbEtTZQ8leimo6hD4neRJZQ4LrL8EYv5BSW6ywwBmA7FCPZ5bXkyG+Jc7Dsr55
         TXtAbMjz8CGVQIBlGFkxHWt7Sgj0ocA2n0cMUWPrBbGgUBtpS9FAG11l6fJSrV4JcBtN
         0n+CFW74eUV/1dWhDKtIkaoJ9AkDrX48ODJjSxz5I66w2P9Wcb0aQildNWWYsFEh1vlp
         CJ1/lFxFsSUb97DZqEHEvEeA9UPbIa+ba5ouwDu/Pj3X1h09Duia3BjNED6vFL7uPBGO
         TuXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XJgdWmt1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cmpujzszQP2cKWC/veQBh8FhwtXTRZeeduWO0N0awRQ=;
        b=SqvcgU+FIz97ENbJuK+i9ZeS4xMbGNOThImNYv7OBVED9fFJI1E9tYmY/ehHfo2RtL
         L9X9vq9McoT0GuP0WlW8d+G49AUDUJhCfgahSh6hTR2PsdzDP2JbtAZcm/0oTCDhJvVO
         cK9/hUXDFtDnxU3isdsbk3lK1ZBA3kNfgoUZV8RGM1RBNB5U16rh3nEULdM1zHgvawY+
         b8+hVCpRvSJMSPbDbhKXBzttO+F/zO8Hl4IcthbwD4meWkNpz8mXQ7cdUlFiBi0nkI49
         pU3Jac6xHzZvrfeRW2bp8lLHrZIzWLOMt0Ad2fdLu+zdQ6gN9VMPSEDUOopMl35Lxx/A
         JcOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cmpujzszQP2cKWC/veQBh8FhwtXTRZeeduWO0N0awRQ=;
        b=CF8E0vmPZLphG37jEPPP3ZoBNWtPug3DIgb6XVSK74hkiFsQNIMZbMq32fTKAUYqiH
         F1GYMHGEMPQVeMCtfoVFc615nd4OIKD7D6W1UFSdyaxJLTCVf+wtWsvc+TyEfPw3UWFO
         Jw+kiJ77KAdG57W5Nvof6+ShJhpXhs6x/Oz+B8C2nen32NvKjuG1krrLtUdKXd005Yaz
         HPEUJUi4Vpj1JUooJ06k738sdkTzCo2WmE89ao+5IivgJaFLBO8whKUXOrO7N7Slxt4T
         mhRsixXNn0TvtcmOcvY6xebjmGgRnO4jMpkUQbt+y/YzOppAedOUwZ/1qNvXni8Q9wZi
         CSrA==
X-Gm-Message-State: APjAAAWqA+rG0DjG4P1JHZkFe237rnRzbY1p5LhUtgY00RKroVuOAZzj
	GW2Qujyp/pHFmjn0FWZ5xHs=
X-Google-Smtp-Source: APXvYqxNusAVZNC0yz4kOleU/17WV/zQ47/hTcoRZvUF2N55gO5ZMkppNNfVnEeGK/NgwipMTs2IWA==
X-Received: by 2002:ae9:f004:: with SMTP id l4mr4269941qkg.316.1571768275719;
        Tue, 22 Oct 2019 11:17:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:ac0e:: with SMTP id e14ls6082031qkm.16.gmail; Tue, 22
 Oct 2019 11:17:55 -0700 (PDT)
X-Received: by 2002:a37:bc86:: with SMTP id m128mr4528335qkf.161.1571768275383;
        Tue, 22 Oct 2019 11:17:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571768275; cv=none;
        d=google.com; s=arc-20160816;
        b=mnKkA2MPx/uEyA+sHL+lV6H896hdgpIIXRt8BejVWhF3XcT+0+9gmEa8+Z6vpUiNSr
         YUEaRFBoZu6eQ0BEclqI/X9E2zIGo5oMxtpr4iFp/X3RZ1dfBmLovvVOWcZhXV50lSwK
         11qHJoQT4yPXQqqifbanYRWwHQLyGkB/tJvxVufL6YFM/LU3qqKeJmk5FXj6GnbXrdHL
         bDrkly55SduNW9AJV1Mr+vOsFKD6lAoIjLrBw/ijrP1JQWHZj3YufZn8EQB+x9O9TSWC
         DhU+1rXN/DgYHs/bkdpI7hnQeEzsoBFHCoKb6ejPhzvZVLlIPS4oYiQTSTM6Vf+2KKg7
         8+Eg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WOpu0OseuiXc08mdI69tOPOopIwWTdbk8nIc2lokKaQ=;
        b=yTWeBN6QU2UOMFahClM5VzKbMCoD+Xv23DiNese49YArkv89nsjgVJicDj0WSoUabt
         RWGHteXTe04ZW69NzbVZg2pcpmUrllHRbiQo/S3TkvwTl7zVCF0zWdEk9fZgUaSZbxC9
         KIdO7SG2gc+OhRmoG4zIfAiZZd0U+keYEBxaixuKTNQKr1skciRtr9PDVgSWRMQ7c1tz
         hGjuJEBhFfcNbI/wMnp4zLh81B56yVwyibqlt99fPCEtB0loqJki4vS0eUnMIfixjUmF
         a/qS6gNLh8OT0MVLE78xgKp8TgGVeA4vOWHowjeguZzjAgPNLOlFVcJMaQeSccw8BL8N
         9NFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XJgdWmt1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id y203si447417qka.4.2019.10.22.11.17.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Oct 2019 11:17:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id b25so3414577oib.7
        for <kasan-dev@googlegroups.com>; Tue, 22 Oct 2019 11:17:55 -0700 (PDT)
X-Received: by 2002:a05:6808:4b:: with SMTP id v11mr4195346oic.70.1571768274619;
 Tue, 22 Oct 2019 11:17:54 -0700 (PDT)
MIME-Version: 1.0
References: <20191017141305.146193-1-elver@google.com> <20191017141305.146193-8-elver@google.com>
 <20191022123329.GC11583@lakrids.cambridge.arm.com>
In-Reply-To: <20191022123329.GC11583@lakrids.cambridge.arm.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 22 Oct 2019 20:17:43 +0200
Message-ID: <CANpmjNOhoyDMFMUz6by3hLtX7aBFk4pXTmzjmWYiq2+z+R5fAQ@mail.gmail.com>
Subject: Re: [PATCH v2 7/8] locking/atomics, kcsan: Add KCSAN instrumentation
To: Mark Rutland <mark.rutland@arm.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	David Howells <dhowells@redhat.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Luc Maranget <luc.maranget@inria.fr>, 
	Nicholas Piggin <npiggin@gmail.com>, "Paul E. McKenney" <paulmck@linux.ibm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XJgdWmt1;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Tue, 22 Oct 2019 at 14:33, Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Thu, Oct 17, 2019 at 04:13:04PM +0200, Marco Elver wrote:
> > This adds KCSAN instrumentation to atomic-instrumented.h.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> > v2:
> > * Use kcsan_check{,_atomic}_{read,write} instead of
> >   kcsan_check_{access,atomic}.
> > * Introduce __atomic_check_{read,write} [Suggested by Mark Rutland].
> > ---
> >  include/asm-generic/atomic-instrumented.h | 393 +++++++++++-----------
> >  scripts/atomic/gen-atomic-instrumented.sh |  17 +-
> >  2 files changed, 218 insertions(+), 192 deletions(-)
>
> The script changes and generated code look fine to me, so FWIW:
>
> Reviewed-by: Mark Rutland <mark.rutland@arm.com>

Great, thank you Mark!

> Thanks,
> Mark.
>
> > diff --git a/scripts/atomic/gen-atomic-instrumented.sh b/scripts/atomic/gen-atomic-instrumented.sh
> > index e09812372b17..8b8b2a6f8d68 100755
> > --- a/scripts/atomic/gen-atomic-instrumented.sh
> > +++ b/scripts/atomic/gen-atomic-instrumented.sh
> > @@ -20,7 +20,7 @@ gen_param_check()
> >       # We don't write to constant parameters
> >       [ ${type#c} != ${type} ] && rw="read"
> >
> > -     printf "\tkasan_check_${rw}(${name}, sizeof(*${name}));\n"
> > +     printf "\t__atomic_check_${rw}(${name}, sizeof(*${name}));\n"
> >  }
> >
> >  #gen_param_check(arg...)
> > @@ -107,7 +107,7 @@ cat <<EOF
> >  #define ${xchg}(ptr, ...)                                            \\
> >  ({                                                                   \\
> >       typeof(ptr) __ai_ptr = (ptr);                                   \\
> > -     kasan_check_write(__ai_ptr, ${mult}sizeof(*__ai_ptr));          \\
> > +     __atomic_check_write(__ai_ptr, ${mult}sizeof(*__ai_ptr));               \\
> >       arch_${xchg}(__ai_ptr, __VA_ARGS__);                            \\
> >  })
> >  EOF
> > @@ -148,6 +148,19 @@ cat << EOF
> >
> >  #include <linux/build_bug.h>
> >  #include <linux/kasan-checks.h>
> > +#include <linux/kcsan-checks.h>
> > +
> > +static inline void __atomic_check_read(const volatile void *v, size_t size)
> > +{
> > +     kasan_check_read(v, size);
> > +     kcsan_check_atomic_read(v, size);
> > +}
> > +
> > +static inline void __atomic_check_write(const volatile void *v, size_t size)
> > +{
> > +     kasan_check_write(v, size);
> > +     kcsan_check_atomic_write(v, size);
> > +}
> >
> >  EOF
> >
> > --
> > 2.23.0.866.gb869b98d4c-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOhoyDMFMUz6by3hLtX7aBFk4pXTmzjmWYiq2%2Bz%2BR5fAQ%40mail.gmail.com.
