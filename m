Return-Path: <kasan-dev+bncBDX4HWEMTEBRBXFIXP6AKGQEXWG5VSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 00DB7293B02
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Oct 2020 14:13:18 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id t19sf916014otc.17
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Oct 2020 05:13:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603195996; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZH57koAPw2EyAE7KMzJwnG2vcMgQal4U1YtbBYUHOopCsawZ016IZfWsUj35BpOW4k
         HfHcyODSkSTiWv4wMhVgP4UDZ2+7hbJeaTZvo1m6k83Yf/XqrM33cDXyPmYskEys6SZt
         my+EcjczUb3sifnPMlBV/4nMgEF8Wiq167OorS4zbSvLoxWet0WjVqXKCJnA9Zn1rjAq
         cbD+oR4mwGyFKcETtfFjl+4f+2+fYLUSTBxXgIp8dzg6W3WOCghzblHZ/zfzjFlpq7b8
         k9idhWg6MDbkFOKXCKhjvfHkORXpX3wPOACwHMnLq/kVt0/Gaz+s93QFykwpCMaCudoL
         8aCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=qptY9m9E1X3liY9osZt8MKebMWtmdFLg1NTnKCl920o=;
        b=wUIaVgpJyrJ1SjgGik9bVbCpUZ4087YKTJ40rqBwd5gQyJDqknAx8yAHZNY+31d8OF
         e4ifby3s4SAHz9IoJA1JVCj8oo6d8dPMIan6hCtOAk0MbwhLQiDt38i8zR5b83UJmwwF
         BmboNiC5op/W0/NBz7ha2ugijPE7o+8IkbmBsMhSvsBYWJ6JfvyF48QZVWzEgNI4QzM8
         I7m3z7k+kqVaERloYEwfmhwpoxLl6VWCphXR+vn01KZzZ1dJxTvWdFri9NRUjij8/Xa6
         qz1w8ovZMG+E8J75wsZixL3xvBazh0kvtwBtl3v79l0GUMDWb+BkCq0BYZSsLRMuH61R
         I5Qw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=O+WQf8Zs;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qptY9m9E1X3liY9osZt8MKebMWtmdFLg1NTnKCl920o=;
        b=n7DynL/bQRcC3Yhpu6JZ/pEGmtDQpNhQufQT49kHq9aycP3lmaRo2HdIGuxZASp4j7
         unvmsvjEjW1veTiWSVJ9rSy9E05vDGWlMibndmbBNOq55UMdTPofAwrX8LBvH4taWHiG
         cfnAJlK9d3qZwLZdM4E1Oplu1/29lFrhYkOB45immrRIy4ZbuB577wN2KRSWxBN5OXsJ
         hPzg124DrKg7IMdvZEVHjAIW5n+kkxBKLQl1P5am2k6T090mRwK1M28h+H0PcRPgz0Nd
         FjeyTkmHMmBNh43QqVBhbL3ih2cc6jGSm7QKyOkScjgdmHyL2LhDCGpZdjBUCPiHoe5s
         4YaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qptY9m9E1X3liY9osZt8MKebMWtmdFLg1NTnKCl920o=;
        b=D2eycyr/+VS49HmkShfDlUFd4EkFExDpyiP3M1iEETx09nMi+u1Pb3YVu/z08JiRoJ
         uqe+YAJCkS9DZn60+/5bwkI0COjwYraTeSVpIgQFd0EM8bEgIwOaa//DOyNljWRI4mxv
         szgmb6NOTK68rBXspT1/5G5TCWYjKy2jUEJ2s1aj6sfUKEPpVOrW4b4szv/8t88uTPV4
         7CsnsDmqe7vlGLYCKr7WzG7MNtd/p3zOSyM7ybGv8HG5CfRwbVXB70up42BXYrHD6AtP
         MtNS6O74QwbMm9Md/PWWWB40LJFBZU+fkWI8quGLnyrWDY6gEwQgjCFtz43l6Hv0dcps
         o9kw==
X-Gm-Message-State: AOAM531WZmuxZwZ0hOtPLX31gNuu/nvW8M0Y4MguyRxmmue1s47RP0Cv
	sX3rTilnPrLnthM5NyOLqh4=
X-Google-Smtp-Source: ABdhPJzg+/sewSCCm8RxXQluHYsRCA5kq6r3qtVi85dXClQfMbZuVD1/QJRlTeBWFJ4qq6eDAGM3Dw==
X-Received: by 2002:a4a:bd87:: with SMTP id k7mr1634858oop.8.1603195996434;
        Tue, 20 Oct 2020 05:13:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4792:: with SMTP id u140ls466462oia.0.gmail; Tue, 20 Oct
 2020 05:13:16 -0700 (PDT)
X-Received: by 2002:aca:4c7:: with SMTP id 190mr1652417oie.58.1603195996093;
        Tue, 20 Oct 2020 05:13:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603195996; cv=none;
        d=google.com; s=arc-20160816;
        b=zPB+qKNvxdYxIqriX8kOijUD4/xK74l7F9zd6l7G5Uk1m0qJrexZb1QgvbhWsAQkAX
         LenJTFunXEHmvl7kg9xPmoI4xnOJGocXlGavGoQbsf9hBmCfk1HlRXHR8Vlew/HvsC9e
         gl7c4MYvlgYyj35UvAn1nK6JchkK/M1PQkxFGJ5an5bTV8Tbd/QEqcmyfXH23yhTHjq/
         RrdXcIARYOd56KALuKsrV7t89yC7gyQpYsxN6vntgbUSSNMeOPS3/b0r9o5wsrTJH7EZ
         hjM+Iz4mAaH9awBDbWLy1YU686CzFXz+iPe3vTZUWc3WiHRYhp/iFHoMYCbTSsLkH2ZK
         iNQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ozLNOPkf0S7L5SxL6HFc1I8U+KuG7maLq27YKTCUYHs=;
        b=wxt6G39BcJSDI0ot2lvJeT1rWauWeIXLjGWOzZirm1CnerAWWKr3gAGnCn3rkubs8E
         TSRUZvRe8vHEysNcbYehDcPy5ItdD/FxFGOXG8AOlwFNFSMCJKPNQxTOSw8fb4wRRMHp
         cHRUN85oTr0ZFu3vKijR4+PC1+cYK5sxSaJnbbGk0iVfFCuIGwEOCmhCFS16OrOK2v0E
         li0ePxHnVlboi7txA5xiq3wXCpUjt78EkFUjSIfMz16OKy5V3PHtEF4oJ6heaI/III1l
         RdVRsnuHK8tYZ+bpXrnRleFJHDzThYWRasTqFgr7Zb7PWrenO2AZqGShIB4JpK3XbkYo
         2Fww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=O+WQf8Zs;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id o22si136249otk.2.2020.10.20.05.13.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Oct 2020 05:13:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id w11so919719pll.8
        for <kasan-dev@googlegroups.com>; Tue, 20 Oct 2020 05:13:16 -0700 (PDT)
X-Received: by 2002:a17:90b:228f:: with SMTP id kx15mr2530393pjb.41.1603195995550;
 Tue, 20 Oct 2020 05:13:15 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1602708025.git.andreyknvl@google.com> <CANpmjNOV90-eZyX9wjsahBkzCFMtm=Y0KtLn_VLDXVO_ehsR1g@mail.gmail.com>
 <CAAeHK+zOaGJbG0HbVRHrYv8yNmPV0Anf5hvDGcHoZVZ2bF+LBg@mail.gmail.com>
 <CANpmjNPvx4oozqSf9ZXN8FhZia03Y0Ar0twrogkfoxTekHx39A@mail.gmail.com>
 <CAAeHK+yuUJFbQBCPyp7S+hVMzBM0m=tgrWLMCskELF6SXHXimw@mail.gmail.com>
 <CAN=P9pjxptTQyvZQg7Z9XA50kFfRBc=E3iaK-KR14Fqay7Xo-Q@mail.gmail.com> <CACT4Y+aw+TwUXkuVsQcSOGTDrMFoWnM-58TvCFfvVSnp6ZP5Sw@mail.gmail.com>
In-Reply-To: <CACT4Y+aw+TwUXkuVsQcSOGTDrMFoWnM-58TvCFfvVSnp6ZP5Sw@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 20 Oct 2020 14:13:04 +0200
Message-ID: <CAAeHK+xoShCZB-XPWauVPxct6eBkxHMZtWWpXCFgCHpiws2NXw@mail.gmail.com>
Subject: Re: [PATCH RFC 0/8] kasan: hardware tag-based mode for production use
 on arm64
To: Dmitry Vyukov <dvyukov@google.com>, Kostya Serebryany <kcc@google.com>
Cc: Serban Constantinescu <serbanc@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Alexander Potapenko <glider@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=O+WQf8Zs;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Oct 20, 2020 at 7:34 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Tue, Oct 20, 2020 at 12:51 AM Kostya Serebryany <kcc@google.com> wrote:
> >
> > Hi,
> > I would like to hear opinions from others in CC on these choices:
> > * Production use of In-kernel MTE should be based on stripped-down
> > KASAN, or implemented independently?
>
> Andrey, what are the fundamental consequences of basing MTE on KASAN?
> I would assume that there are none as we can change KASAN code and
> special case some code paths as necessary.

The main consequence is psychological and manifests in inheriting the name :)

But generally you're right. As we can change KASAN code, we can do
whatever we want, like adding fast paths for MTE, etc. If we Ctrl+C
Ctrl+V KASAN common code, we could potentially do some micro
optimizations (like avoiding a couple of checks), but I doubt that
will make any difference.

> > * Should we aim at a single boot-time flag (with several values) or
> > for several independent flags (OFF/SYNC/ASYNC, Stack traces on/off)
>
> We won't be able to answer this question for several years until we
> have actual hardware/users...
> It's definitely safer to aim at multiple options. I would reuse the fs
> opt parsing code as we seem to have lots of potential things to
> configure so that we can do:
> kasan_options=quarantine=off,fault=panic,trap=async
>
> I am also always confused by the term "debug" when configuring the
> kernel. In some cases it's for debugging of the subsystem (for
> developers of KASAN), in some cases it adds additional checks to catch
> misuses of the subsystem. in some - it just adds more debugging output
> on console. And in this case it's actually neither of these. But I am
> not sure what's a better name ("full"?). Even if we split options into
> multiple, we still can have some kind of presents that just flip all
> other options into reasonable values.

OK, let me try to incorporate the feedback I've heard so far into the
next version.

>
> > Andrey, please give us some idea of the CPU and RAM overheads other
> > than those coming from MTE
> > * stack trace collection and storage
> > * adding redzones to every allocation - not strictly needed for MTE,
> > but convenient to store the stack trace IDs.
> >
> > Andrey: with production MTE we should not be using quarantine, which
> > means storing the stack trace IDs
> > in the deallocated memory doesn't provide good report quality.
> > We may need to consider another approach, e.g. the one used in HWASAN
> > (separate ring buffer, per thread or per core)

My current priority is cleaning up the mode where stack traces are
disabled and estimating the slowdown from KASAN callbacks. Once done
with that, I'll switch to these ones.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxoShCZB-XPWauVPxct6eBkxHMZtWWpXCFgCHpiws2NXw%40mail.gmail.com.
