Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKN2425AMGQEFSAFVEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 626569ECE1A
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Dec 2024 15:09:51 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id d2e1a72fcca58-725e8775611sf3051565b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Dec 2024 06:09:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1733926188; cv=pass;
        d=google.com; s=arc-20240605;
        b=NbjBE3BKIIXYAWJhTncDzRKYePteRc5Dl7nwriTNEh4iyk8LweDZo/Ti28nxPzm1QF
         WMcAsqKfZPlCi8sk7WBaOfGEA7GnWayh87FrGTZWUr7NC170G0xMI4AuCjBkuBRlAelG
         yL9gdo9gjtfA7aynWAuL6I8qFjiO67HQZp8OBfLT8E5USrrgPa40TnHg0qxAlqJaTir+
         /mA2S8YYa5Sorlwv1HpK+fiqjuXwc1xeLnDMrKzEVlBZSPERuXfH+0acGitHrUhSajWH
         8QvJv/7L1qkL3xEdE0wuELm9WKABusBiT0vglLrWzoNMfhUGD3bz+xj7FBg7ucpvAbk+
         gVrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/anoQD8DReahjNtDdgSnUPrrc/dm+uvQ3ZuplSQAWWA=;
        fh=AOWxR9heEgxxSPV/w+15QAoTTD2wS1O8q27bxNUTt1s=;
        b=P3FXq/zYGO4pyPZUZOUoay4+Z/kURzUUxcW1MgLT/ZejLa4x6OFnfJzO6pswBvg08T
         fw0lX18hthh2sDml5tSnwBxGwQWVLF0Ep8TcD2CdoXIOxctU6LxE9aGk8ZDI/aUqg+ca
         gAzSB3+BBpaLZXn58zH4BuhQL2ZObVhjlhOHcoddksbHZibqnrFLErbiyLYtfNVQfndN
         47IQTnBRnMomxM6XQcyrFIpL551YWW84QBfulVg2WV7pgGPpcsKntGKCE9fLjcVO1R8U
         0Y/t3AxlgwDX9fNgF47IkwECl5X1xwnt2eex4PFAyInVPywIeZUGf8iJWbGpm10v9AHA
         NSeQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4bgJpuOO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1733926188; x=1734530988; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/anoQD8DReahjNtDdgSnUPrrc/dm+uvQ3ZuplSQAWWA=;
        b=tVRoXms+wcwOMyK42GvgnUd3PXQbUic2XpldvhNojUuZ8+ne1coMFuO6okqWgCkiFM
         /9mKw2/Ztyl7kwpJ5tWvgKqj1UAJer1msGe/FlHpV9pgsSGYVKBO8aXdqp++HH/W6OFP
         cV/mmVSQcVsBMI/EG8jm/zUtXTj9CsM5D5ADzIj6tG5PKc8QYz3wquBplGVhatBi2X6P
         1G86KV8EZQfx+00wG2dsQbASDWxHUcy6lp+acFAXHMyriSApJeLX/MZlhtW3vZgDfl8I
         eKC+XMQw6NaN4whkQTI4hUOWCUFn6UEbLBO4+R5M61VdlPEI3lFkaof88kgZhIxObFWN
         yMUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1733926188; x=1734530988;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/anoQD8DReahjNtDdgSnUPrrc/dm+uvQ3ZuplSQAWWA=;
        b=QDlNY2ypvNkbbjM/gvclzYw4/zE22Qipz0AfsPnLBAv4V+vux0J2AJnU4OdV5jQP1J
         J3/DffuqzV/0i7K5mK7y25QleNQz5xJmGfy2iNLIWP9enG1QX0ZpKjUTchzcz/0fhfeF
         Z/yRFEtXJD4jMhOCgE/CRLcq6z/79DgTWk6kumad3arawS4ZUgcOyaSzNOTFmE0xh8/R
         9AAu0F1WZD/8huGtKPNXclTkK68TUTbJM7oybjpkNzri8dkiKsGEJm9i7Zm16Mj4rl0U
         AbjU0Gj7ZGpB/HmzbSqJIM5k6KLF0GpYWxmrt8IcBNPvpl6/EL3Y66UFK5lKswW6dB0m
         0dkw==
X-Forwarded-Encrypted: i=2; AJvYcCXkUyjOnuk1VaZbXSMmQcEifeW0RcIVNtN1eCiHEL2EgTfor2qeyQPNpB1gEQcE7siGLH2K5w==@lfdr.de
X-Gm-Message-State: AOJu0YzzXqQK18GkEXCeimwevDY9IThJjOF00xYa+CRjBBVbln0bC6GB
	qvRveq7xuHW6x2PRIe5Ng7+9FxJkso6S3q4dGgh8TrGkjx8W2meY
X-Google-Smtp-Source: AGHT+IGRMg4IJ6ByRIN3evrkkdaE6ZtGm6QXdmfBLoGr7dOFwCiXzE/2SnJLHM3a/sexdEXoV4I8hQ==
X-Received: by 2002:a05:6a20:d491:b0:1db:e338:ab0a with SMTP id adf61e73a8af0-1e1c121f62dmr5947879637.8.1733926186069;
        Wed, 11 Dec 2024 06:09:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8ec4:0:b0:728:e1d1:39dd with SMTP id d2e1a72fcca58-728e1d148d2ls1624679b3a.1.-pod-prod-05-us;
 Wed, 11 Dec 2024 06:09:44 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUNvanrqAVByNp6rt67iE9HDJKGjeodWdVVBNMbubqnWOtcHqsRIJVH+p1N/BfQ19TxE0tghPh0220=@googlegroups.com
X-Received: by 2002:a05:6a00:2e1a:b0:725:b12e:604c with SMTP id d2e1a72fcca58-728ed3ac8b7mr5122066b3a.4.1733926183761;
        Wed, 11 Dec 2024 06:09:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1733926183; cv=none;
        d=google.com; s=arc-20240605;
        b=GjKu/jVrbsb7VW1k/XIiNKziL1KDgGqWU5+qbUmdkdqTHX8LMga1uLrkTwS3+ikV58
         z1qWxRHfSVAFqnhAVtG5+S5ySvOFi3gWfYn6yD4F7JkSv0l5iPkL7Ji8H4Q33Nq0Ss3Z
         oQygGFRLzu3O8Ys26dPcM4Bao7VGxoYZdGE8uCbqmpI9XIO6GCxMAl3BXlOG2cN+OQ5t
         coqoqJkf/Bq11mUZRfkKCyTDjHrSWydb44TOnL4njG2cCfgolf7bG/9O1cSB7e4AXU4Y
         IDoy5J7bm/NIvhXI4UGOpOLLCWB+ZKGYjas0Zt11sVsRnT5lwKL4PiLoCpDO991/PIMb
         J1wg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yGF/cctnrxaftIwc3nmoT+49gK30u6v6P+AQjfZtHW8=;
        fh=mnqPau+0O++Dgk/V9Qjro8Tn/1+jY+MJUKrdv46BTms=;
        b=BCjJArod4KCrpXpPWLpajrUyt2NuuNLzoYBrOrVn7RrCjk1csXwSHuoaC1tn4oAbzV
         wYvO6NqX/+5tBidOJj7vzjrszmsWiFmCNv05Lldxg5Rj6bW7VtgsKjwgv+P1ZOpiobun
         UV9nXfota5k+0eyMNfJVDTVAyKql43uFnz9z+cCiYEmsjRIPa+rPcHHVCDvrvMXA7gTS
         S2QLCK2T1Sr25fm1oJe94m1HLErbGKc8twgzWSkutg7R9XmBW3km96njDtWPpv2CXwLm
         nLip1JCNHYmG14Bt7alH+7j2gR2xKw3/fiti1deBC/rsO5p6kLFk5XQ4p8gZm9sMRSOD
         eNbQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4bgJpuOO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-725e7718802si367140b3a.3.2024.12.11.06.09.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Dec 2024 06:09:43 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id d9443c01a7336-215770613dbso45568525ad.2
        for <kasan-dev@googlegroups.com>; Wed, 11 Dec 2024 06:09:43 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVzZ26tvIq8M34pwkkhk9uM6qlmlt/dCXBWAHUOHjnaoK6cQRkrBI1QIQGZKlFKnJ9JXihGC9zsfS4=@googlegroups.com
X-Gm-Gg: ASbGncsmoF/yqZg54fUfQVzJPCJIgDGOO63Oc3qrE4/zby37hYGqMngpQpgdMR7UF33
	EYdOtDqzpE4H3p4gYO1/waZ0Ht3PjZW56ZEZavdDlw/Y3y3Tn32MNYCAhAB67/E2r
X-Received: by 2002:a17:902:f60e:b0:216:2bd7:1c49 with SMTP id
 d9443c01a7336-21778535677mr56186705ad.29.1733926181789; Wed, 11 Dec 2024
 06:09:41 -0800 (PST)
MIME-Version: 1.0
References: <20241108113455.2924361-1-elver@google.com> <CANpmjNPuXxa3=SDZ_0uQ+ez2Tis96C2B-nE4NJSvCs4LBjjQgA@mail.gmail.com>
 <20241115082737.5f23e491@gandalf.local.home> <CANpmjNM_94fmQ025diHd9_vKtRxtDbSYaOpfBbshNQYEPQmHZw@mail.gmail.com>
In-Reply-To: <CANpmjNM_94fmQ025diHd9_vKtRxtDbSYaOpfBbshNQYEPQmHZw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Dec 2024 15:09:05 +0100
Message-ID: <CANpmjNMmUTuim5PYgQ-=Fk_bjz5tbxm+xbenzsnjXWmqu_04MA@mail.gmail.com>
Subject: Re: [PATCH v3 1/2] tracing: Add task_prctl_unknown tracepoint
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Oleg Nesterov <oleg@redhat.com>, linux-kernel@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=4bgJpuOO;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62a as
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

On Fri, 15 Nov 2024 at 16:06, Marco Elver <elver@google.com> wrote:
>
> On Fri, 15 Nov 2024 at 14:27, Steven Rostedt <rostedt@goodmis.org> wrote:
> >
> > On Fri, 15 Nov 2024 13:00:00 +0100
> > Marco Elver <elver@google.com> wrote:
> >
> > > Steven, unless there are any further objections, would you be able to
> > > take this through the tracing tree?
> > >
> > > Many thanks!
> >
> > This isn't my file. Trace events usually belong to the subsystems that
> > use them. As this adds an event to kernel/sys.c which doesn't really have
> > an owner, then I would ask Andrew Morton to take it.
>
> Got it.
>
> Andrew, can you pick this up?

Gentle ping - many thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMmUTuim5PYgQ-%3DFk_bjz5tbxm%2BxbenzsnjXWmqu_04MA%40mail.gmail.com.
