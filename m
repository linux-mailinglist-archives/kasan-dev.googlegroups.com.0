Return-Path: <kasan-dev+bncBD3JNNMDTMEBBSGBS3FAMGQEND3VMNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 23093CD182B
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 20:00:26 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-88a316ddbacsf47110626d6.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 11:00:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766170825; cv=pass;
        d=google.com; s=arc-20240605;
        b=T1LVeDy7t3Xgu2DytzPPcpT0UjnA1x6UGVwe8UppvNuOkWoTECIcP+CNtrlDcQiJa6
         eGDh13ely0kq3juJ6CrljclV7wje0AgRKDsz1BsF8eYbK2AdnCU6EtDE80or+JKZG0iz
         moX0awomIVTrDBW5xRsj4gXa4rnma3DKRQPgtNkUOWQlYhf0hI464GkeuYLAcK9SAnT+
         JBPXDhcT3nXMq2vuH3EuIEUwz8kftERF4kN3M4mks+ayNHHmVvciPX52jQ/Df//t9KvK
         +x/3bzZ2/uLjbNx3Kwr+jNoPGelhGTv66+qfPWd1MSo5JVTVNmO75EfdwdxcrXpkUmgR
         Lm5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=4Ty8+6ipj3MpB8FXBQz9cwy/VW9H/kn31GzkRclMkL8=;
        fh=Pq5APeRKp0e1lFi0AzYIY9suhbKI79IdeGdf+mR3NT4=;
        b=Bsntm6lyqSZlrJ9rvPJSZ+aRESdW6dhR0ra2gCjX453TqveYtua2BWhUdeVl3sh3lo
         +SVoYs8NjVElnT5994MvAGBhbG/lybDn5jZvdtfsNWqqJpJ0yCb1UDwR+301xlpj8VkE
         iGfyUtmXyNYVbSY37a+caMxchtpMcnsbN6hbYZlkGTEZ+MB5npgMFhyr0Y0MRwiHpg49
         9+IuVL0hmj7ycHdbfUXJJy8LTQpAiekaHJejHi4DPpE1dBwbW56sFcTUW0iJ/t6t/4VU
         WxIt0BqK17E0SvBpv+LbzjVi4GBn2XTfePubUupV731ADJR3D54rD6Yp1vsu3cMPbnvS
         +9zA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=UjD9F4cw;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766170825; x=1766775625; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4Ty8+6ipj3MpB8FXBQz9cwy/VW9H/kn31GzkRclMkL8=;
        b=XMWyX6gDN2s32eftk/wSNGo6qID3O21v/pn5QbKQ0Qm94AyWTDa2adanQoJMxwuLOS
         GHkSFCrsvm+7MuJnKIYfU3Fb2XDmSJs3X2aRGeGfjhanW8Wv6O/tRETA+OZGcfGEqYAF
         W6vVCNWSTTRTXqm47mZ7cPSloylcjJyzb48jhCDXuKPLVUKw11G6cNu83F5teD0WLhrR
         xtLCzjPZu+pPU6PSdGx9qJU3zPF2pYxFXRFG4ZN8XeNtV/bID6K4eKD0eFmFsewO8AWs
         HoysudzG3Fq0bZglcUPkozSzxAC7PKokzO1BGJyQx+HJa/HUAaArISiUulyQRSl0nYrx
         tOig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766170825; x=1766775625;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=4Ty8+6ipj3MpB8FXBQz9cwy/VW9H/kn31GzkRclMkL8=;
        b=kGLR6tOW9QCBcSHPHvLiwbPXhMCsRbYmwGP/IDVj1dh6N/yhEx4BSsEtvbqfKLEvcW
         0McpPqR78nLjXa/KOYTlDrtdYPco1agGpwbKrUV/iHdeAVMJgdAKGQGRKxKnNYSn1AhS
         O3nGUXt3nq1Th004u9K+XGNE74l7kUYbGpvzLDAUjcWvZKS4HjOsZ/P5EwJpzf4Gp5gk
         XByDcREYzVP9b+EinsX3fZDQrfAk3tUFsQU/7itJcboxewdrQ6fgLFZJfRcnllqGefeT
         nOVH97a60SCfj+nWbgSpogPlMah6+Ne6G3Gu8JqrWeEj6Y99rmuk/xZ6QZ68g3Nk298v
         MA8Q==
X-Forwarded-Encrypted: i=2; AJvYcCVn86JEIhNzdvtKmXHbGCYTeHjytssJQx0nEWKfBYM4Fzig1ZV4q8k0wsWrzQXWUhF6d+5I3w==@lfdr.de
X-Gm-Message-State: AOJu0YyjmTB5Ebgd1P21emgb2TOzkCERMbhzkExH1qwRPMj+vupdwvji
	3KOkRW83P5xOirKPS1nUzdDE6mmu8POHiJj4af8939310XObXT1t8Q+Z
X-Google-Smtp-Source: AGHT+IEp73HKf/FhO5iEhkacigVYxOvwNPP5o2zhoSFwwyLYQovOEN7tKY6o9uI/obbww/vrmTS7xw==
X-Received: by 2002:a05:6214:570a:b0:888:4930:7982 with SMTP id 6a1803df08f44-88d8712bd9fmr72948856d6.70.1766170824288;
        Fri, 19 Dec 2025 11:00:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWb2HlQIZgoxI7X+ZAA0TWb2rRQOlJlws0dcGu2HAYQFFA=="
Received: by 2002:a05:6214:3018:b0:779:d180:7e3f with SMTP id
 6a1803df08f44-8887cd8fedels144425526d6.1.-pod-prod-01-us; Fri, 19 Dec 2025
 11:00:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWXxzGZYsIdcRD341sGXMUJeETHvKXmsyRkLHpAwLLplPFlbYfqQyXCgNemEoSy3mHVUWUOSRTLJvE=@googlegroups.com
X-Received: by 2002:a05:6122:1b8e:b0:55b:305b:4e37 with SMTP id 71dfb90a1353d-5615bec271amr1116249e0c.18.1766170822647;
        Fri, 19 Dec 2025 11:00:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766170822; cv=none;
        d=google.com; s=arc-20240605;
        b=cXH98MzQZNyzyp+dYgVLimJtX5lHmUy2B2B8uq6F6EZjyTOz0plasKncl7FFkTc/Oy
         zFa7rTPavCO3Y3dy3Z+IYBBy1mzs4R2irsJw27bZ303k2eHWDv9o7IntR4WSmI3zh5sF
         zQC5hMDHWP/ztmZFfep3zPsdiDY26PBpu9H1yKKHwZJyVuQMOaD2qZC9e57AJUfgyYKm
         ayQfLtGYgKptElxVW/QivcLKqDA6RYlqgx1w/LblHkJEtO5AcuL6F2bMof1SRKZYPpQC
         JqfIK3tQOWfTQ5t3apNUKGUnlDYu0lGHwXfxEpE+yAC/bqA9CV6nfU4mdVjJwUSfQeB/
         9xsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=ePVSZjUMvM5UwcnAVR7UWrqjg1Vrw8j5vSX/Uk6yy0Y=;
        fh=91aBFnGEfvUJK5rfVeJcSAU1chZtpnzNnKR7WFwoZ/M=;
        b=L6xYlVm8jKPYnLZs5Tol6y+dbiIMTSSrQyt4M1futSRbhGNkATLdTqsGhoWEJMNCxh
         CJh/CHZSbvnhRhZmhdlzaLewYR7x2AxcCX0TqulDKc+0PTDZOR+vWkjDHySUfk0pXxa5
         09JOjQatnj39tPn+UIhaacgsdrFeX0OGSXcn9J+8QCf5fwtLOOg+uAEQSe1qemKjjm80
         E4L5deQngB+5RJGpDMGWDvH7NlxrJ4LJfurod2nlSsuJYBbmCEh3nQlSKsAg81VEWx24
         A1mSuYz9sruVCqWjXS7Md3r8noU6sG6MCoE1EfBq7BO08AMNTBohcUgkaE8L/XIwyiVE
         f6FA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=UjD9F4cw;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
Received: from 013.lax.mailroute.net (013.lax.mailroute.net. [199.89.1.16])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5615d1ebb99si99729e0c.3.2025.12.19.11.00.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Dec 2025 11:00:22 -0800 (PST)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) client-ip=199.89.1.16;
Received: from localhost (localhost [127.0.0.1])
	by 013.lax.mailroute.net (Postfix) with ESMTP id 4dXxgS5FtLzlvrT5;
	Fri, 19 Dec 2025 19:00:20 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 013.lax.mailroute.net ([127.0.0.1])
 by localhost (013.lax [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id XxrjPaU1Y7x5; Fri, 19 Dec 2025 19:00:13 +0000 (UTC)
Received: from [100.119.48.131] (unknown [104.135.180.219])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 013.lax.mailroute.net (Postfix) with ESMTPSA id 4dXxfz4M91zllB6t;
	Fri, 19 Dec 2025 18:59:55 +0000 (UTC)
Message-ID: <1df1695e-778a-45da-9348-61f9ea34a862@acm.org>
Date: Fri, 19 Dec 2025 10:59:54 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 06/35] cleanup: Basic compatibility with context
 analysis
To: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>
Cc: Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
 Will Deacon <will@kernel.org>, "David S. Miller" <davem@davemloft.net>,
 Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
 Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>,
 Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>,
 Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>,
 Eric Dumazet <edumazet@google.com>, Frederic Weisbecker
 <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>,
 Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>,
 Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>,
 Josh Triplett <josh@joshtriplett.org>, Justin Stitt
 <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
 Kentaro Takeda <takedakn@nttdata.co.jp>,
 Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland
 <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>,
 Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
 Steven Rostedt <rostedt@goodmis.org>,
 Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
 Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
 Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>,
 kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org,
 linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org,
 linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
References: <20251120145835.3833031-2-elver@google.com>
 <20251120151033.3840508-7-elver@google.com>
 <20251211121659.GH3911114@noisy.programming.kicks-ass.net>
 <CANpmjNOmAYFj518rH0FdPp=cqK8EeKEgh1ok_zFUwHU5Fu92=w@mail.gmail.com>
 <20251212094352.GL3911114@noisy.programming.kicks-ass.net>
 <CANpmjNP=s33L6LgYWHygEuLtWTq-s2n4yFDvvGcF3HjbGH+hqw@mail.gmail.com>
 <20251212110928.GP3911114@noisy.programming.kicks-ass.net>
 <aUAPbFJSv0alh_ix@elver.google.com>
 <CANpmjNNm-kbTw46Wh1BJudynHOeLn-Oxew8VuAnCppvV_WtyBw@mail.gmail.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CANpmjNNm-kbTw46Wh1BJudynHOeLn-Oxew8VuAnCppvV_WtyBw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=UjD9F4cw;       spf=pass
 (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted
 sender) smtp.mailfrom=bvanassche@acm.org;       dmarc=pass (p=REJECT
 sp=QUARANTINE dis=NONE) header.from=acm.org
X-Original-From: Bart Van Assche <bvanassche@acm.org>
Reply-To: Bart Van Assche <bvanassche@acm.org>
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

On 12/15/25 7:53 AM, Marco Elver wrote:
> For cleanup.h, the problem is that to instantiate we use
> "guard(class)(args..)". If it had been designed as "guard(class,
> args...)", i.e. just use __VA_ARGS__ explicitly instead of the
> implicit 'args...', it might have been possible to add a second
> cleanup variable to do the same (with some additional magic to extract
> the first arg if one exists). Unfortunately, the use of the current
> guard()() idiom has become so pervasive that this is a bigger
> refactor. I'm going to leave cleanup.h as-is for now, if we think we
> want to give this a go in the current state.

Peter, has it already been considered to make the guard() and
scoped_guard() macros more consistent? If there would be agreement that
guard(class)(args..) should be changed into guard(class, args..), I can
help with realizing this conversion.

Thanks,

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1df1695e-778a-45da-9348-61f9ea34a862%40acm.org.
