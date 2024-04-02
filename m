Return-Path: <kasan-dev+bncBDQ6ZAEPEQIKN7VQWADBUBCTIS3MY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id C1B1F895A9C
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Apr 2024 19:23:52 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-516a213a18esf1645152e87.2
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Apr 2024 10:23:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712078632; cv=pass;
        d=google.com; s=arc-20160816;
        b=MayB5Tt4seJK9in8RIFPB5j99Ma6/DscVj5cNY5i3J+cor7yDoFgjXyhhB4IWp08Nt
         QXEHeUCQdwKDmUTpPu/QxHs8YSDqOKe1BS/CfGy1rpBuyzcPGUY7GkrNCxglNMKMYgCM
         LqF1RnbzBe12dUD/61SeS4igdznxlR/l72yIMpA9j1aFVRhzCXHZJIBX5NLxkXJPDRQ7
         gL+PeSLalpT/YZBBrkSgOzmDuUrEsSh1PTi2ROoHZnSE7rkSFnw2VI1Dnoofc45me6X0
         QNNpCa8jZmY7sadcUULyGheA2fUQu6bAH0OMHQ/FgudEFoGc/DpFyZWUPxNE2zsM7CXC
         4N5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=p1O1fUEikOzdH2Ex8CeSIU3p2MfAEwKu6baSN1AG1u0=;
        fh=Wxr8FnuZqCq2pVSzfXOsu+zy8+AbIYgNZAGD/9jsjgM=;
        b=E4g8vulv8OY3sen6800JDynYw4Y3MudFUo4uzfA86jeJtKUeWjkuETknlbTAefyM20
         05ONxyrrWpVzDRIym46S+eGV5R0oB9nK27HGwjzODYo8kkL8vV7cP0cOEDKOLMdLnJso
         DGfQnhvQlVwM3CBuN/w6eo0c8JIVORkoosMObOHFaVfzKRV15AgiYldawe3gqgJwxOX6
         pN2C7F/KUVBlbEii0RBj7cvXxyO18WFYMRLQBnNPHFKC3qYXBvdGHMXYMDg3S7GnkHjk
         E9iAl11A5tUfM9M9mtsu6hREy08EaQq0+aRnHcRJ0SJs4Xg/J0Vdvxe2hYqvNY+xCVlW
         DEPA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QSuM3btH;
       spf=pass (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=jstultz@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712078632; x=1712683432; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=p1O1fUEikOzdH2Ex8CeSIU3p2MfAEwKu6baSN1AG1u0=;
        b=mRRz2p22E3NfXdfKUUb70CPgz76/ORFTH6cKn83cMVHwtlLjMRUVSX5gwJhPoiyW/O
         ALlRNirjkRrytIyaZE2C129jSCotK3ho1BKP9GsvYe211dR8VW87OFa8tvkGVcff7aRj
         OrohcjHoBPnXlJ6wOPdtk9uGC9BuXUvHQXsae5Kn+FhSMF59y3KO9ir7wT3rggucEcV5
         QG6voc00FMj+HE4aETOsxvij2kw8JGW7dS5leeoIC7/670toWwPUw60dkcnP/3HTBmOG
         S3rY79gFi0s0guD/W4jj0GVZ60WqwuyK+9bABUSAINOKEccb77T/Ua3KoL7FAVN8/IDm
         1ZiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712078632; x=1712683432;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=p1O1fUEikOzdH2Ex8CeSIU3p2MfAEwKu6baSN1AG1u0=;
        b=rMbj/h2fr7jOq1cusK/1yozdJ18OOLGb51v5gmiLl2bkQmx9LbD1WLf1sOe7aEqZ8+
         U8Wa2cCuJOAOUyGKURwoHEL5i9iW4YxWlcjDOA1LGnguhwIKDRKHyE/7I3QoB8iDaSCz
         OCMVBXKvV1mx6UZMtSFBFANCNR6dXlgJj+a+9EAvnV0SaB7uMk7xP0MwWynw9TMKfNp0
         krZTdwg3qxAV+/0Jd1YDty/FFqJ3CjT40iH2EVrIHM/spYVKGmEJ6/lH4MtvZ8Q8++e1
         9VqiwR4fBpeJzdlnZBqxIB3/Ds9oT59PyFfRFWsns9tfQAIB/wz3UddqKEcIlsl6Rlo1
         +EcQ==
X-Forwarded-Encrypted: i=2; AJvYcCXb2HXO79QUkPwUv1YKhz5I+44mqiVqLVdWLLJNWg7TSKtW445tHE5J/uVUZcPMRCcKSvUJUAxfcpXyHYtbP5OjwOPEKGmSGA==
X-Gm-Message-State: AOJu0Yx/q+fBxwRQVP6srkI+J3tPxQ118ffToEGepdLb+N9g34Z0YeFC
	h7Oit2wVNHAnYKU8u1mxp6XUKP0kqc11EYdL55afqWGxW94t8pPX
X-Google-Smtp-Source: AGHT+IF0cMDxttVk5ngKNj6x301DBg3NL9LfVAUCcC2/H3ApAYbk/D0lSC5KkeJXUtTzlMy8+B+sxw==
X-Received: by 2002:a19:2d4b:0:b0:515:c113:381c with SMTP id t11-20020a192d4b000000b00515c113381cmr2215426lft.30.1712078630878;
        Tue, 02 Apr 2024 10:23:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e06:b0:515:bebd:eca3 with SMTP id
 i6-20020a0565123e0600b00515bebdeca3ls150378lfv.2.-pod-prod-05-eu; Tue, 02 Apr
 2024 10:23:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVF6yBT5LvetJCvuK5VrfZyO+785WL8tEuXIi/uXCLcypI4oVGuBOhnWRjbIJshE8560uPW9KaV6/fYctiKxeYwYudgJEs2hZc2LQ==
X-Received: by 2002:a05:6512:3b3:b0:513:cfcd:f25f with SMTP id v19-20020a05651203b300b00513cfcdf25fmr1804251lfp.54.1712078628363;
        Tue, 02 Apr 2024 10:23:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712078628; cv=none;
        d=google.com; s=arc-20160816;
        b=O1D8v3HyZxfnhMeQq5yPxWubYBoJ1N4bwcL57todRc7pH0gnVMBJtnG2XxLEagJgaJ
         3ffwKHjQyaTMPjDACjIrBRGyIASduxb2TIkaoozuuZTLEuN9WComV8jEi4uIsSUpEUKw
         hCNR6GC4ih4PgwnUd8aYrl5b1vCCBigUvvnBLvFznvqSNrHQUafJoExgiTYupORt7QsD
         mYG1mgbSm/3CiznecDItVjZECqxZtAFXRcc+N7h2vfLjZIxqnUYZ8fho3FrzAgX6OZV+
         VP50rnwaF037ODPdEZZ/vCic0+L58ZEJkoGIhrE/ZRUd6NkcP3PaT6Q6xUqU0VSEC3lF
         yuNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=AnglfsZWKsoCgYV9GRi7FFVEehEIz6FLkc6jkCsCjpw=;
        fh=uOWSVaMxaFSeI2cTdgZpfCg9d6VChvMH2+GBPGQJYgQ=;
        b=XEuiwqPGspxqdcWt66C4dHo/U2KgHpyWqaeTHhxe8rjyMG8vgxYo76oXOqXqHdTJnW
         OF+/EuKm6cZyFS2ZW/zCOLMyd5f7qhditevWkhDfVxzJ2bE6vrd6K/rKfF/1HPh5inpW
         JQQbjUsEogpeIb1kl4j0F0Ub1qmwGOnJVACUKSpbvavAScREOXqXgHb/7hE2jqHvYspR
         kJdkQ0J0PCv6UdOEEu0URzzojTSuWb7am2w6cnoU1MjMtSCrAL6eueluHm5+6nfiW0jF
         D7OJx/g4H4fKV1rE5H2neVq4HMRac5efi8betxYTI8E1IBevcY+nRUkANJ/+suTfTA10
         EMhg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QSuM3btH;
       spf=pass (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=jstultz@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x336.google.com (mail-wm1-x336.google.com. [2a00:1450:4864:20::336])
        by gmr-mx.google.com with ESMTPS id t13-20020a056512068d00b00513c1ff7958si378230lfe.1.2024.04.02.10.23.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Apr 2024 10:23:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::336 as permitted sender) client-ip=2a00:1450:4864:20::336;
Received: by mail-wm1-x336.google.com with SMTP id 5b1f17b1804b1-413f8c8192eso7855e9.0
        for <kasan-dev@googlegroups.com>; Tue, 02 Apr 2024 10:23:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV6jBTa0t6KYv+Uaminv8N7YKw1TkeMWw+T2ycpbNL8I94KO+asM5Yxy00ttb6nb04e94ngdgCkGIDAvtbXUZo4jphJmrPOHeX5Cg==
X-Received: by 2002:a05:600c:1c20:b0:413:f41a:ed1b with SMTP id
 j32-20020a05600c1c2000b00413f41aed1bmr807067wms.3.1712078627548; Tue, 02 Apr
 2024 10:23:47 -0700 (PDT)
MIME-Version: 1.0
References: <20230316123028.2890338-1-elver@google.com> <CANDhNCqBGnAr_MSBhQxWo+-8YnPPggxoVL32zVrDB+NcoKXVPQ@mail.gmail.com>
 <87frw3dd7d.ffs@tglx>
In-Reply-To: <87frw3dd7d.ffs@tglx>
From: "'John Stultz' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Apr 2024 10:23:34 -0700
Message-ID: <CANDhNCqbJHTNcnBj=twHQqtLjXiGNeGJ8tsbPrhGFq4Qz53c5w@mail.gmail.com>
Subject: Re: [PATCH v6 1/2] posix-timers: Prefer delivery of signals to the
 current thread
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@kernel.org>, Oleg Nesterov <oleg@redhat.com>, 
	"Eric W. Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org, 
	linux-kselftest@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, Edward Liaw <edliaw@google.com>, 
	Carlos Llamas <cmllamas@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jstultz@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=QSuM3btH;       spf=pass
 (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::336
 as permitted sender) smtp.mailfrom=jstultz@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: John Stultz <jstultz@google.com>
Reply-To: John Stultz <jstultz@google.com>
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

On Tue, Apr 2, 2024 at 7:57=E2=80=AFAM Thomas Gleixner <tglx@linutronix.de>=
 wrote:
> On Mon, Apr 01 2024 at 13:17, John Stultz wrote:
> > This change does seem to cherry-pick cleanly back to at least
> > stable/linux-5.10.y cleanly, so it looks simple to pull this change
> > back. But I wanted to make sure there wasn't anything subtle I was
> > missing before sending patches.
>
> This test in particular exercises new functionality/behaviour, which
> really has no business to be backported into stable just to make the
> relevant test usable on older kernels.

That's fair. I didn't have all the context around what motivated the
change and the follow-on test, which is why I'm asking here.

> Why would testing with latest tests against an older kernel be valid per
> se?

So yeah, it definitely can get fuzzy trying to split hairs between
when a change in behavior is a "new feature" or a "fix".

Greg could probably articulate it better, but my understanding is the
main point for running newer tests on older kernels is that newer
tests will have more coverage of what is expected of the kernel. For
features that older kernels don't support, ideally the tests will
check for that functionality like userland applications would, and
skip that portion of the test if it's unsupported. This way, we're
able to find issues (important enough to warrant tests having been
created) that have not yet been patched in the -stable trees.

In this case, there is a behavioral change combined with a compliance
test, which makes it look a bit more like a fix, rather than a feature
(additionally the lack of a way for userland to probe for this new
"feature" makes it seem fix-like).  But the intended result of this is
just spurring this discussion to see if it makes sense to backport or
not.  Disabling/ignoring the test (maybe after Thomas' fix to avoid it
from hanging :) is a fine solution too, but not one I'd want folks to
do until they've synced with maintainers and had full context.

thanks
-john

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANDhNCqbJHTNcnBj%3DtwHQqtLjXiGNeGJ8tsbPrhGFq4Qz53c5w%40mail.gmai=
l.com.
