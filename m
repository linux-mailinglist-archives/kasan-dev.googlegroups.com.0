Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKHB57EQMGQEGGCGKHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id D08E6CB8A14
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Dec 2025 11:38:33 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-4ed74e6c468sf15286091cf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Dec 2025 02:38:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765535912; cv=pass;
        d=google.com; s=arc-20240605;
        b=OgkWaFVpsKumuVy9z6+tGFiLJfnJ5gdoveL0TKwv4NGKjR7FJEPbHFudzRuwelGb/5
         e43pnhJxxtU2mhyNP+wT57yvD4TcU+ORwo/W9HHTEyLn/uU80dijq990tDB8YArwWRY1
         zCIkihFPjugfJ+88pFb17qXBdFckz5ZRxCiG1cdMtwgC1cJMYPN9cYpwYfvX1p18RUlG
         niDn40lULXdjJ3hPSAs9TLJUO8ixMNIL2fq5B+eW8BJvHY06KlgynlMchZeKpuInb949
         OSjbu/006+z1REdeo5GYcEaUlf33134nsZubfGIWwOuXDtRkIiHFM1Kwoxc+AMIBFdH/
         BC+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PmJ6m+v/LmnRs/BmR+0v9TZ7KSrA0hpUXXhcloFcSjU=;
        fh=Btb+hzVZvSrAECCOcuFF/UqVH1msioC3X5DTzbcJs30=;
        b=LsO7h/Cg7VH1w05gOohIXEdb5tvk8BKcJKToFzAnEgAQiYjqAszgSXHjukbiRycHNi
         JVj5HcUJrzqH14abYbNkW1vkAntCdTf7bmWL2r2Jwp3MvAzYwAXWLWRK0l3F3dL4Qahx
         Mktfl9fdMpb8dz72z5D6O65ZjvhgwH6CaZkg76cHYKcS1ZzKYsBJ9Gj7Rg14eEylRL61
         Tgel1MJfgNTZ/FUud5LlwXvr0GbKMnEltZuFBLshOZSMWnTxW9Fg8WzeBvuC9JingTHm
         Qhqe+zjkShLJ+BFfq/CA/zbzCM25o38ZhLXs9eBfaVwh2n1htBrfX0Y4ECl7A2leTFSz
         bhWg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zIaXJbOq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765535912; x=1766140712; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PmJ6m+v/LmnRs/BmR+0v9TZ7KSrA0hpUXXhcloFcSjU=;
        b=NFS8lSNTp4UCQHWH6ULVnY1X4/whiwqWo9BqqPq9p5TqZn9IzCHNabXxBUOB0Tvtx6
         zILLGUmJ0ZydVJ3aQkTvvJGmmf0v/xRa9tvjjasjJx4gHRxaZgKP6DqX/J6jVkYtQxFH
         /eqrfYQTpFKeMYlI/7cCZlg9oErxgM8d6lw1/4n/UilWE+3dTT9jE3wygTecTB1KuAkK
         qk64/sTKk9XVW4Irfyl5tQcP8q29X65KiK1c/uF1+KHqvIS6XBBDUO93/BHVpFojnaGt
         Po/fZ+4qI5gbxxQz5+8mwb9OK/pd0ZszXBFAH7iEOcRcGPX9GiOa8JnkPX8FKMwsm7JT
         Q1GA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765535912; x=1766140712;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PmJ6m+v/LmnRs/BmR+0v9TZ7KSrA0hpUXXhcloFcSjU=;
        b=kQ9565du3nVjtn/eP8ZFri6lIeK+2nji28JfugAns+So94S3SqcA6wjIEdF27ffJ1l
         NAXbR/OjcWt2BMPQ7JTO1ZlATurSvqivPTr5ZtFVV9M12/TE1FZ/WzJ25h8l840EOecK
         zem2iJ0GxWwgYdMLfHsGDa9C2NXdnlVXxMlsiukJ6ltIXwTlRHzLDz6Wxi83H5ot4SUN
         tMeGKhJrz+o5TkIlekh+bmHj9hLX4tiPtI4Y4yCCW6QzzdLwnad3ECUKd9x+PRMetI9t
         dSaouCOY/k7ek/jgbLW3DDgovpQ1IPfIAoGCk0hSPhjS1t6EW6MG1dyFCYiLANdPiCK6
         hKMQ==
X-Forwarded-Encrypted: i=2; AJvYcCUY7h0g8Fu+yjpJBi1NSTuq3kLQk0q2b9ZDJOchKabUUwN2ifcv6pKZXM4W1rgZBcoK06YVnw==@lfdr.de
X-Gm-Message-State: AOJu0YyHXGuotAR5aLiI8wh+PWV3ctB7f+gAxlMgXyzSXS4GLkMto4P1
	0aqsSmO72A8AjrF5VzyMnTIHlAK33ztrOF+xMtQuBpy1GULif35joUe5
X-Google-Smtp-Source: AGHT+IEHECbMcNhdnucFESoRfZjjpAmFS0OEuKRGZYbU0CQYbv2+JoR0xUFQ324RDxbFJPBQtnOBmg==
X-Received: by 2002:a05:622a:5912:b0:4f1:ca52:9035 with SMTP id d75a77b69052e-4f1d05054b0mr19848181cf.24.1765535912282;
        Fri, 12 Dec 2025 02:38:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaBZyTR/D29fVUr/eT4BBJg+yND9sqjvsaMJMjTck2pdw=="
Received: by 2002:ac8:5f0c:0:b0:4e4:600f:d8d4 with SMTP id d75a77b69052e-4f1ced6ff5fls8526631cf.1.-pod-prod-08-us;
 Fri, 12 Dec 2025 02:38:31 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXbZ1Rat74Of3EDCQ6Yhq0Wm3isLjUKjPL6qrKC7fBKXn8JCasvaMMvpJnerdG7ywTESSgBcuMTlT4=@googlegroups.com
X-Received: by 2002:a05:622a:124a:b0:4e8:a664:2ccb with SMTP id d75a77b69052e-4f1d062a521mr15014521cf.63.1765535911492;
        Fri, 12 Dec 2025 02:38:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765535911; cv=none;
        d=google.com; s=arc-20240605;
        b=Ft7jBkl50Z5JD9sGaamo7s7ya6qH6UzQAAYeqeYET2Yil6SHX+DWcKbpu9mYCkYKT2
         PzuMatP3bLgjZvbZiF9kSuLAqIQCAPAqtGx6VHKoCeujZmrpYgGBb5maKJusH4KWxMcU
         k3RV8s1i7PHpejYY2L8ccfh/0wHDAR5ewGC6VopbQ5UYgpG6zc2cwILLzmua5FsOvCIU
         C7p5KyNzstiH9eWaOsl6sh64UxSW06zCzpJlqYcgLJHMaqZFJPHK2O8BKHrhHfMXMcsl
         taow5nnMsvuX/FGhF3pAMGrcmAV1IFLR1LtnoXSktPkxM/F2O6+jUOc1VjceyJD6NjVE
         jEMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nctQCqtW4QYyeaejz8PEb38w/v2g7uc6tb41WntjKNI=;
        fh=H0FXEUDsLqN8C4H8s0t7KRgjVPiOkITo/tBHZIw6q7c=;
        b=dK41CnfLAXbc7innLTorIEDbTcoeW5QRIlx4tPOkZ6yTdM2PqXdibUWfL6pfssXjeA
         +IszgGQPyNYgpxZfAmE9k/S+TCQB4uTBhEUZvpJGMtqaCBfNme6/TicqS0gRICBTxsjI
         EsL+Ag/qg2F6eyJOUui0dw3+7C36Q9je/596OhSDyDqHCHPs3xPaPcxm3j7lmA45p7K7
         72eGd6rQMgGIU63Y5rhIxmLDcy3LoNdK5yt9k2TJsUnYnvg+YvqK6XU0Wz33GG/QPcDD
         HY10WS1ubldmKfYm/tP5ALoARizkm9c6XWa6K2nvSEqDz8eIwXfwc0L10vEmACJShmiI
         6zEw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zIaXJbOq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4f1d7b36a56si160951cf.1.2025.12.12.02.38.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Dec 2025 02:38:31 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id 98e67ed59e1d1-34aa62f9e74so1261784a91.1
        for <kasan-dev@googlegroups.com>; Fri, 12 Dec 2025 02:38:31 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWmLpMUV954ODQvvWl8RVKZ4RPLgRzOuNxmq+OBQfehYIsAcIUgQ74y8zooqJyQnO1nUm1fOk2HZHY=@googlegroups.com
X-Gm-Gg: AY/fxX4A2gdUD3BaGWu2JeZ07x7HeFfGsBHnYaQRqRvnNKSP+0x8wbznxUS0ngi7oES
	sK2vBn9JuOUoDXTcE7CecbB68AldZKpiLftImJI959QJVEt8/jdFnIOCZTyxRnYTYgYstVda88e
	Q1xm6EKuUziZJe/BHxL14k1F011be1ToMkEqFcwzLo7Yok3qrhhRqRpEuUBFRZNcVGyy0s6ybNX
	etY9I+fcvoMYVNYGWtXDY3t9VMksRX4gE2B0s1xq+FJgA7cn+AiJ7wlioiOr7fx0Zt5oQKJgPiZ
	AcWfLAxLQkTE0fKjYKnxEZjE6Oc=
X-Received: by 2002:a05:701b:2719:b0:11d:c86c:652e with SMTP id
 a92af1059eb24-11f34ac540dmr1125346c88.5.1765535910093; Fri, 12 Dec 2025
 02:38:30 -0800 (PST)
MIME-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120145835.3833031-4-elver@google.com>
 <20251211120441.GG3911114@noisy.programming.kicks-ass.net>
 <CANpmjNOyDW7-G5Op5nw722ecPEv=Ys5TPbJnVBB1_WGiM2LeWQ@mail.gmail.com> <20251212093149.GJ3911114@noisy.programming.kicks-ass.net>
In-Reply-To: <20251212093149.GJ3911114@noisy.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Dec 2025 11:37:51 +0100
X-Gm-Features: AQt7F2qnWyV-H6zf6AeMnZTuFb_nb7UwLLraoghpFqSJ0q6RecRlENqaq0woPuo
Message-ID: <CANpmjNPcw5AnpLpaFvyRee7mH12Ym-NKTx331xXEusK5zpiscA@mail.gmail.com>
Subject: Re: [PATCH v4 02/35] compiler-context-analysis: Add infrastructure
 for Context Analysis with Clang
To: Peter Zijlstra <peterz@infradead.org>
Cc: Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, 
	Will Deacon <will@kernel.org>, "David S. Miller" <davem@davemloft.net>, 
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, Chris Li <sparse@chrisli.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Frederic Weisbecker <frederic@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>, 
	Joel Fernandes <joelagnelf@nvidia.com>, Johannes Berg <johannes.berg@intel.com>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Kentaro Takeda <takedakn@nttdata.co.jp>, Lukas Bulwahn <lukas.bulwahn@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=zIaXJbOq;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1036 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Fri, 12 Dec 2025 at 10:32, Peter Zijlstra <peterz@infradead.org> wrote:
> On Thu, Dec 11, 2025 at 02:12:19PM +0100, Marco Elver wrote:
>
> > What's a better name?
>
> That must be the hardest question in programming; screw this P-vs-NP
> debate :-)
>
> > context_lock_struct -> and call it "context lock" rather than "context
> > guard"; it might work also for things like RCU, PREEMPT, BH, etc. that
> > aren't normal "locks", but could claim they are "context locks".
> >
> > context_handle_struct -> "context handle" ...
>
> Both work for me I suppose, although I think I have a slight preference
> to the former: 'context_lock_struct'.
>
> One other possibility is wrapping things like so:
>
> #define define_context_struct(name) ... // the big thing
>
> #define define_lock_struct(name) define_context_struct(name)

Note that 'context_lock_struct' (assuming that's the new name) can be
used to just forward declare structs, too, so 'define' in the name is
probably incorrect. And to avoid more levels of indirection I'd just
stick with one name; if 'context_lock_struct' isn't too offensive to
anyone, that'd be the name for the next version.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPcw5AnpLpaFvyRee7mH12Ym-NKTx331xXEusK5zpiscA%40mail.gmail.com.
