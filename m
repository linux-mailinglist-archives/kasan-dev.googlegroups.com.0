Return-Path: <kasan-dev+bncBDQ6ZAEPEQINJLFMWADBUBEVO2UP4@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E6CA8945E7
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Apr 2024 22:17:25 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-4155e2ed5d8sf7799845e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Apr 2024 13:17:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712002645; cv=pass;
        d=google.com; s=arc-20160816;
        b=nNpP35Xm2BKZ6ICUkWyJ5igvN17r5xLXV9XB7Oq/vy3mACQ7mgEO2HfbIFJdycVvl8
         fpYVDQIa9H43RlgspYWROjzX3k7IL1derzvD1Ygee4abBRS+kr+wo6acOZsSs3hfnLFI
         86rzprR8+jn9tfxn47U0iRE3TQTllXVQjQQ7dIvqwGz+os4emEMts+ZiKNFfuQ+6pdXd
         7qXIOZpO335J6H8zDyozlyQaYlK/FwWcfix9Uetb+R94j6meVrYECR4axxDIJ9RszKQ2
         o2GbvxDjcd9xHINvKCT2z6/6BSkDHsJmU3B5lo5TucvvJpcAupFOqs4nam1MBdv/jzT9
         y0tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=r6A2SxHBqYVC6L9Zd5ZRsXZCJN2bM5aE2qFi0+dIuPU=;
        fh=sVddeyKE858EHY2FKT9JayVv815w+nnyAFFF6MOzVFY=;
        b=MfaVYw2qH1FZHUgTmuNBl7Jb0Togdxdu9yqqrOK24RoOPJavES7GIqUcbvCQivhc1v
         ql/HobOiGi5U3wVKcBD9HczkRYCWvVpgDM2XKtnifQkuDPRt7u5IQTUf0zcwdfmTVD3B
         Rr2te1qBM63p7V5v2IC71yx9nSIn7pCyO8GQal/a1ARSBx0HTZHWiV7lusMr/aH1IsqE
         /zM4ULpMwWTJL2hExZAGo6ig6KKjX26uh2ozHFof5yXKeHMCqa9qj54Ubrlfdr37kmXM
         LQhr7gFL1JWbnE7RNoF4e6k/W4SNl4VqRKlwT30vpX28pop/kbTPWVQeugT4UI7u4IFQ
         oUww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=y6vb2WgH;
       spf=pass (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=jstultz@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712002645; x=1712607445; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=r6A2SxHBqYVC6L9Zd5ZRsXZCJN2bM5aE2qFi0+dIuPU=;
        b=oOXLol8TeDW9YqcmF1xVr3IKBR33ycXaaEuVkxoW/3f8fdwNKO4qgS4ASqIN8ML/oN
         vtziXQtVZsTjNZBfZuHAClr2MaZShp4YkbYnqO3K1DlFO13hIDxMYFWWNPDff7fYhatt
         IihRslgADojIJAGMEhftaowSlhopHhBVu5vbG+7lsfQa3jxrkagwUG/rUN5c+/YjtD0A
         bnLX/9xRfP0HpR3HxPN1R7PCn5fskBdk4ZmT6qGHrXsAsOIp0R3BtnTQPTk/w6ZzJobG
         pwiuwgPHInf8ZRcfR25nsAXTfoHooU7b2QvVSv1uf36qX8rHeKexQJS56IrkoSPk0y1h
         RZtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712002645; x=1712607445;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=r6A2SxHBqYVC6L9Zd5ZRsXZCJN2bM5aE2qFi0+dIuPU=;
        b=W3cOpZxdb3criHjWgyBv5EO97l1ZYtbuIqiPVa1kWZ+bQ07iJppHN9QZqNNlf+Nmju
         1ztkMhdZnCMcd3UBkxj6+J6y97/itzPK3sE8hb+w828Im5h/Tih4rCJVqJPQTc22yTh6
         fdH4PHC87ZtX4/qZ3gnzwe3+cCFas6Z5DNIPYJkEvGvWCQNrGvzj/KUmt45K2iOeE8hO
         HTWJo6CaJEtRnih234ccnnC6CZL4GW5SAAn8/jW8kOQosFJ7hVJEQzANdjpYUoocINpb
         xsyAKifGCc+5jCXD3SGQSlITT1DQuw6Mf5KgfFRnL4/3nWpRYhmkTdRRrKJDvAO2kY87
         GPgg==
X-Forwarded-Encrypted: i=2; AJvYcCWBSpdPwh/EsDKhV5MtjMmgYZ6sCkyb40hudK58G9+PCnKMLf38XxpZLBPIN2CgQZvKEwhsyaxRc4beEAtzvZZyL938xxkQ1g==
X-Gm-Message-State: AOJu0YzDwJ4yJKDkJuqjAhIj4vLYf1TdoFX4FKDqysLEyLo0GOeoJWEt
	JQFQFAnCC8UDUGsTY+aFceBYcK6VLRi1lS+EAie7YRaX1Xktzo5u
X-Google-Smtp-Source: AGHT+IETKomdA8ITNjkNoV19OsmW+ItHZlZVWjeh5YOlA9jG4P6G4QAYie5HPVJuRtr2yWIcXykziw==
X-Received: by 2002:a05:600c:3545:b0:414:7b98:da01 with SMTP id i5-20020a05600c354500b004147b98da01mr8489330wmq.7.1712002644557;
        Mon, 01 Apr 2024 13:17:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4fc3:b0:415:4b49:9edb with SMTP id
 o3-20020a05600c4fc300b004154b499edbls1238260wmq.2.-pod-prod-00-eu-canary;
 Mon, 01 Apr 2024 13:17:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUsQcXJkKWgz8atNyfHjpjMA97qUwJwDCovzVmszpIqFg9AxmHsLPPPPd2QrjKhKmjRXlGNVwPJtZ+/mM5Rb1DUojtD6KssM0E5fg==
X-Received: by 2002:a5d:654c:0:b0:341:b5cc:f805 with SMTP id z12-20020a5d654c000000b00341b5ccf805mr9817270wrv.5.1712002642437;
        Mon, 01 Apr 2024 13:17:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712002642; cv=none;
        d=google.com; s=arc-20160816;
        b=09xSqxYPtNfPsry5XrfYhG9WyNw/BQIrbJ3ehQsHaGNatrqLXCi4pTfdPqVcn0Iq54
         hwoiy3tD8ciUACqzZYKAt2QuDLuvBphetzvQTsOTnUSTpvegaRWPZ9rB/q0bybKMYkCG
         hYmN/49S7lwb198QNqF+QZ+4Apb1NbYucgAMSTcDIFsa+ojsWwLsG9WVX5x/QfNBLGR9
         P0FgajESzUuYifsQGptGpKaZxj6s9Cc4I7fWrHHu47oThE1rgQiDlClvxBKu15XH3gNF
         EX6VVm2NCU4P7F/seYQeSjkKpynxezU8R1HIM7fHtgYBtH/2Y+AXdWTQsTmTy643XIhu
         CDPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=J3aFjL6s1SfTb0uIG99KnzgQCy9He0FDmkud5jyqZjA=;
        fh=wI+3bS4Nw5cORVh5JiNMP6eWoZUqOjMmAakzcn2Iqjg=;
        b=jYBBCiHfCfgwwVrQoPuD3LYmWuJ2Qi2pQTZF8gbqb/FdZTNwp5aS4LLSgk4+CVgd0x
         CyBZGj3/X6qG5fAOwmfAM2LFWJ8Dj9wNzG+S6925T/aUQvg1fieH/pSE5tbiOCtbAEfy
         4o+8gIW8smkLKEhimL/Pmek/PI0GTTzaOt/nGGGACFQ7khbsVUWHB6uB6fcypq/6URSl
         yGrZetXLtFg30K4tgfpzzpr6PCjDb91Np/w59WSzVXH8c+oJrCsCekdI/4Ct/1DmlUsv
         2HGpdRXV55Yx05L4qsYnNIMIvD4NH0NYuDSCVLo4T9RdV0H1LrBiH2wSQpbe9F61QCrn
         +L7A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=y6vb2WgH;
       spf=pass (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=jstultz@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id p27-20020a05600c1d9b00b00415e36d5f12si9643wms.1.2024.04.01.13.17.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Apr 2024 13:17:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id 5b1f17b1804b1-41549a13fabso224475e9.1
        for <kasan-dev@googlegroups.com>; Mon, 01 Apr 2024 13:17:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVyMQDFOpUSjBtVaOH9ryTJIZgOBrNHbpe+Nnl1FtKxehc3Rb5uV6BwpHxWgO4WTkunXJZzCIAHUQiMLhjLPjx0VS2rTDTRj9/Q5g==
X-Received: by 2002:a05:600c:3587:b0:414:800f:f9b1 with SMTP id
 p7-20020a05600c358700b00414800ff9b1mr640853wmq.2.1712002641819; Mon, 01 Apr
 2024 13:17:21 -0700 (PDT)
MIME-Version: 1.0
References: <20230316123028.2890338-1-elver@google.com>
In-Reply-To: <20230316123028.2890338-1-elver@google.com>
From: "'John Stultz' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 1 Apr 2024 13:17:09 -0700
Message-ID: <CANDhNCqBGnAr_MSBhQxWo+-8YnPPggxoVL32zVrDB+NcoKXVPQ@mail.gmail.com>
Subject: Re: [PATCH v6 1/2] posix-timers: Prefer delivery of signals to the
 current thread
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Ingo Molnar <mingo@kernel.org>, Oleg Nesterov <oleg@redhat.com>, 
	"Eric W. Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org, 
	linux-kselftest@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, Edward Liaw <edliaw@google.com>, 
	Carlos Llamas <cmllamas@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jstultz@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=y6vb2WgH;       spf=pass
 (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::330
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

On Thu, Mar 16, 2023 at 5:30=E2=80=AFAM Marco Elver <elver@google.com> wrot=
e:
>
> From: Dmitry Vyukov <dvyukov@google.com>
>
> POSIX timers using the CLOCK_PROCESS_CPUTIME_ID clock prefer the main
> thread of a thread group for signal delivery.     However, this has a
> significant downside: it requires waking up a potentially idle thread.
>
> Instead, prefer to deliver signals to the current thread (in the same
> thread group) if SIGEV_THREAD_ID is not set by the user. This does not
> change guaranteed semantics, since POSIX process CPU time timers have
> never guaranteed that signal delivery is to a specific thread (without
> SIGEV_THREAD_ID set).
>
> The effect is that we no longer wake up potentially idle threads, and
> the kernel is no longer biased towards delivering the timer signal to
> any particular thread (which better distributes the timer signals esp.
> when multiple timers fire concurrently).
>
> Signed-off-by: Dmitry Vyukov <dvyukov@google.com>
> Suggested-by: Oleg Nesterov <oleg@redhat.com>
> Reviewed-by: Oleg Nesterov <oleg@redhat.com>
> Signed-off-by: Marco Elver <elver@google.com>

Apologies for drudging up this old thread.

I wanted to ask if anyone had objections to including this in the -stable t=
rees?

After this and the follow-on patch e797203fb3ba
("selftests/timers/posix_timers: Test delivery of signals across
threads") landed, folks testing older kernels with the latest
selftests started to see the new test checking for this behavior to
stall.  Thomas did submit an adjustment to the test here to avoid the
stall: https://lore.kernel.org/lkml/20230606142031.071059989@linutronix.de/=
,
but it didn't seem to land, however that would just result in the test
failing instead of hanging.

This change does seem to cherry-pick cleanly back to at least
stable/linux-5.10.y cleanly, so it looks simple to pull this change
back. But I wanted to make sure there wasn't anything subtle I was
missing before sending patches.

thanks
-john

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANDhNCqBGnAr_MSBhQxWo%2B-8YnPPggxoVL32zVrDB%2BNcoKXVPQ%40mail.gm=
ail.com.
