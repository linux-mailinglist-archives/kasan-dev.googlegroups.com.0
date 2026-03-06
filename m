Return-Path: <kasan-dev+bncBCSL7B6LWYHBBH6UVTGQMGQEMTSTAIA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id CIJLByIqq2luaQEAu9opvQ
	(envelope-from <kasan-dev+bncBCSL7B6LWYHBBH6UVTGQMGQEMTSTAIA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2026 20:25:22 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13c.google.com (mail-yx1-xb13c.google.com [IPv6:2607:f8b0:4864:20::b13c])
	by mail.lfdr.de (Postfix) with ESMTPS id B39F0227085
	for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2026 20:25:21 +0100 (CET)
Received: by mail-yx1-xb13c.google.com with SMTP id 956f58d0204a3-64c9ebd16e0sf16748069d50.0
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2026 11:25:21 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1772825120; cv=pass;
        d=google.com; s=arc-20240605;
        b=T/ZeihNpsLAyvIwGzSYkbS3lylD5KsSrv8XQ/yMEIoGK+bAbb8CQv+nwh/PrMU0adj
         OczyOAz6gRAhEidU/PRiHw6xg0RcSfDlaiEugLcVP2kvv0ieICqFdc680nnRNC3TAFp+
         gmLKkxjA/EcOI0msbsE/bccgmKikO4ayPNVcQr0l87XvxUff6AQqZLk6ilZ6L/eisurF
         3pyHpbPkwOzsZ3/cpRRIq/FmMs4uLk5rNgqbP3uimaV+0uuq50aUpvwsA7gg19CdYPaG
         nOK7zlnJcbcSGE4PWLxeivPEyfy4he6uLXuYv8gGZqKiMYPp25F2vyaVXyDoMAWZ8ayl
         q58g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date
         :mime-version:references:in-reply-to:from:sender:dkim-signature
         :dkim-signature;
        bh=DkNGs9Oj4+VYm/0uBfYInSSqn8H0EhmBx8xKYSw7UZU=;
        fh=JhNVxrqDgoLZR4UXY0BTMvz0sqbQhGCNmZ9Qas3i8aI=;
        b=ki06wCXc3QLHmP/FbwrQ2333DN3IoiGlDOmI60WZGp6qE4qpfPC9p0XOurwwNFKeq1
         RNVZQCA77GcWyRDlPqBIAsHjM6psEOv5PAN6vsUxmHfdq15ajN3flt3YoNR7d0fpgjqV
         LxvbjLBnJj4vRp2j+LhVfDxI78BkBstSOPrSMoo4/U4cOlii/X3uff4qcDAz/yS0EQNr
         bQ2kcnaU8XwH9A9laDn5RPGT3TUIzVu6vDG8PBEGjuuae6lcm/aQuOpsMXu5qjdJN47v
         vx4dCu+N7Cqe7AQtiKErz5o0ewqHWb7QqwkAnhOabFAW1KDhvtTMr/fjoHDxTLCEcdjS
         kUwg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=D+1k+Tew;
       arc=pass (i=1);
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772825120; x=1773429920; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:mime-version
         :references:in-reply-to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DkNGs9Oj4+VYm/0uBfYInSSqn8H0EhmBx8xKYSw7UZU=;
        b=XgSyMolaucOXNTQEsjCsuDSr6LsFwGxPpY9FmUvSJQqIaw/dPy+D8k7ACJzoCeCvKK
         0rZAgsWUpkctJNS9gYOvwYT+5+JyaE0sUWql7MLyhyo/Hysc2oTQnGAL/z0rwlVFTJz8
         jgihK+x6IPrxeNIU/yRDJ6imMHZHGIKJS2+Ygk2Y96HhyuC27w7GktRhezdpjem0c0he
         nZ2xMRhwSv12vk20/xGBLHdglimB6oBYfdLoPPc4p3kKy0yEg7AAuSPlKRoPkpI6A1DL
         xgbNhQfVF+svZCzQ0ew82+dVNXyKZ3Zq+uAgN38gJsKreE30tkRppk0S+y49XW7rs6G1
         S/pQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1772825120; x=1773429920; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:mime-version
         :references:in-reply-to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DkNGs9Oj4+VYm/0uBfYInSSqn8H0EhmBx8xKYSw7UZU=;
        b=YtPiIr+Rq2WJVbSTjzbSAH8j3SQvdVLjcoQWxolMLH60qr8m9ikonV0KzpP+3ZAusJ
         RF7/SHNc0B/QNf3cAUuRvoxb6wAFtZaKzBCH4tT+N9UC1c55yCc9UfiRD/vEW6vfsiDy
         D+2DJ+oYPihJwYJFCxCKR00+YnZsQUFtZCHFtpIFUyOzE2m2vA/p9sJ2fW7tAo8G3nXC
         jh9bVRMhb0Gj78UcIN7utAEjFyGZgHaRqz48yONOW2FZVGf6CYp/7/AKlZSaJcgORddb
         W4/gcPmV2RC6j/U/X2NKopG4xHKJWALR8YJ7tBVeUXegP9ER9fbXE3Npqmw0xBfzqAsJ
         2abw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772825120; x=1773429920;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:mime-version:references:in-reply-to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DkNGs9Oj4+VYm/0uBfYInSSqn8H0EhmBx8xKYSw7UZU=;
        b=TtLid/ECebgnw+UqdZpfgEOCokvMUZh9lfgRLJsVLkJcz7WZwOCCPHVpZRdsvWIWRf
         k0LCLK7IMW2IVBrQ0b4zJ9HktllSzPZkiF+7GyX/gnYqHMeOT/WAlx+akKz8n23gOJvM
         +urvi7dq7NDnM9JCh8bA1uhH20VFI+g8AHVUV/zQkQU3yzxkFbET7IG6P/T3A9h2tBPC
         ADTjgM0S4ppyIX3z95ivjneYjC/yI8cpfJKG7imt6Uuvfp3B58FBFB0nF9klBWfqExX/
         JIUftHL3c6Dp+bZ/9h5LTabFKxRjto07s8BvSRGE3Pd6br8cy8dvNoxJNdjDDbEkhWcc
         DZLQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCWatmrZ9bOFvhEJ8yfaGoj+YZQxJzV/Gjm+B2NJ0g6Y87xtZQ9c3xr07UskqPZVIcq99bcb8Q==@lfdr.de
X-Gm-Message-State: AOJu0YyvtOoa/j+SVa+VEr53CYTxosfnbdBdvxA1Nl7BLbgrmJ3lbSOB
	S4dtH7YPFlSGpeFBP+vveCh0N0mRFkJ+CJKF61K0cErzYN35k8885Vm8
X-Received: by 2002:a53:b5c6:0:b0:649:9795:620d with SMTP id 956f58d0204a3-64d142c6c3dmr2222833d50.55.1772825119968;
        Fri, 06 Mar 2026 11:25:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GXfjR4IcdgVE+QCyO1tuMsWR5gkbFk+I7r68Ri51fVfQ=="
Received: by 2002:a53:e026:0:b0:649:3fa4:9e9c with SMTP id 956f58d0204a3-64d05216cafls3062760d50.2.-pod-prod-06-us;
 Fri, 06 Mar 2026 11:25:19 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUfHP8vtdFiFiVKTBGCu/nK0ItliY9LVkG6cEY5Z2YT+xAX3gNG8oNHNISZApx7SQX0icke2l9gkfA=@googlegroups.com
X-Received: by 2002:a05:6102:3f55:b0:5ef:aeff:8304 with SMTP id ada2fe7eead31-5ffe61ca3aemr1339761137.33.1772825119062;
        Fri, 06 Mar 2026 11:25:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772825119; cv=pass;
        d=google.com; s=arc-20240605;
        b=jzICNR4fK5RCD1miI/GNrWWzQljtg7hTQ51f9QdfM3qAn22SB8vLlCXhD0XzDqDtfk
         8e5s+xjrV936FHByFsgshP0EkU2f0d1pizzj4qOoZtHm9du0hIALtX+EXlVVsXYIcDWe
         5wcwtmxuGeRjUhN4GG6be/3ZLlkDEuaUYOFCsqM3zzldlooHFtgjZH1hB6Lh/GDiDefl
         Q3zQn/WPxw8r+IDP5PW6FU8S+kJ+psvkfYFSwXjj5RDsIaYb4F+Gs8RUCc5w1EAzst5O
         JkkQpRKvHg/m/pv8U2ENENxZR1BzUzQq0g/1j3rikgizcQ4F9yJ24SitAj81r+7ZsM3h
         WoGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:mime-version:references:in-reply-to
         :from:dkim-signature;
        bh=lY6sP4liFUCfsR0JZcNZnSXYRH2hTABEqRhwR3Jxfn0=;
        fh=nUopJG8T5tyOeVXCFFtYHMAkawI5o3vTyz/9obpxwmE=;
        b=V2FRbEE5ckZK0N4Fkxpqi26UlLNIjdVH2jdhUeMoHUI+qpwAnZ1Jexa+mUFf6tFJus
         78mzqlHrhcgZN7aeA/RnkFVndjlAsaZiKo5vHMeB7/ym9ke4TVt123x6B2DvT1gjOG8+
         rBYtzBHhgEcHRSPBgSU5WLMYTWCvvK80MgOkK/NrnJuTneHbbBmNKD7jhBnH233uOa7f
         2NgZ4Lx63u+yPNgafSXD0t8NqmWH9ifOOAQnTka9lTT+JTlDaptPmTBKV+iEnusNREhU
         OQyVC/zbNR54ZbANB8KFpFJ+v21m9rBjBo9NUeGuyc/5lIfoT31+VC29K8hM4SW/7wyd
         KJHg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=D+1k+Tew;
       arc=pass (i=1);
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x112b.google.com (mail-yw1-x112b.google.com. [2607:f8b0:4864:20::112b])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-5ffe859f4a9si59471137.1.2026.03.06.11.25.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Mar 2026 11:25:19 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::112b as permitted sender) client-ip=2607:f8b0:4864:20::112b;
Received: by mail-yw1-x112b.google.com with SMTP id 00721157ae682-7980969ffdfso9026327b3.0
        for <kasan-dev@googlegroups.com>; Fri, 06 Mar 2026 11:25:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772825118; cv=none;
        d=google.com; s=arc-20240605;
        b=W4ynaRDD5NChUQ8zf9nGNZdtU8HPADxCrC2XPPUk0jRn86wTCXVYIg0JoX98cPOOOO
         mjrj/fZB7XXW3CFRRBdruHKpT3cX3JkK6/Vz9rp2O3hu9yTloGI8wJFgyPzbjoVZa8ki
         dy+7F8/iqKtQDtm8v/kFm+6+CF48WBXETkv+aCLPcLmhR35Y2Drnw5DgFbko29opxZY1
         BCLaE6elV97nSLQEtQOB2NP+JphoHdy3wA5NVKNRIb2JWiJY5rcV+LTqN58GnV5ljSqk
         Pk8a8qnac1Mjr71V7DBt6j2nFxE1CZx7HaexjNfkftU/A0i+h8zVub16uXonqkG2VusO
         fg/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:mime-version:references:in-reply-to
         :from:dkim-signature;
        bh=lY6sP4liFUCfsR0JZcNZnSXYRH2hTABEqRhwR3Jxfn0=;
        fh=nUopJG8T5tyOeVXCFFtYHMAkawI5o3vTyz/9obpxwmE=;
        b=lAU/UrICfbi9r/8KmZO0SQU5VMM9Cg94wCX0BedTXgziB0HdgadrKayhcZN762THna
         /sT6CwxHhrsJnSHdsoS5cMsFvSMaWWtAahnC6WXsfNCTxPvcDSr6B2cwgZkmtDtWkx0F
         W+qdn+At0oKEr9Pa7APrAiNYd19I9+Ku7qf3awhNaUQkpfb+6rq5sk9oX+oJ+BMZ1OU4
         xz8dmFthYGKq9cm1jplqwKWK2FNNAlHVHzlpz7hKe2RodzShh6qnW5RlMaT4JiPkU2af
         jsol/QvYBGbOcni8NTPWysXUFQ5ED1K0+d4jXHDcL3zPI5jEmFma0zxfPvTmNmqbjiYY
         9B0Q==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCUKPTirLLt3CL4Ik3a9vr6n6kw/2u8FfuxlrzztDgTXH/HA+zs7misDjfsJSfI33qDaludfIBP84Tg=@googlegroups.com
X-Gm-Gg: ATEYQzyjVBvBvE6+Mk8USpzKblSVXIBjlW57NKR/znvqfapv1VQSQRWuhQGFq2syYO0
	axQgd3POqNJfstu5N5Zf06lT97kqi2Bj5Rgohs2tsM6A9CRil8W8jHwtUdRvXHmk/jf6Pum21GM
	VGGIUImGsDBho/4yO3zi1bHSDgG2JPvX0Yo2qEGS21nuUtURgA4ndl9t5m+/c46EafygcS3210+
	Ock7pOcQ7EevLdcWVtQx7M/7EQc0hASMm4anGBXsJuGA7tMruF8AZGIzCRZeJwRRkEqUR9EbG5y
	dMdPNQ==
X-Received: by 2002:a05:690c:15:b0:798:5ce8:f46a with SMTP id
 00721157ae682-798dd6f5b17mr24082977b3.3.1772825118598; Fri, 06 Mar 2026
 11:25:18 -0800 (PST)
Received: from 95991385052 named unknown by gmailapi.google.com with HTTPREST;
 Fri, 6 Mar 2026 13:25:18 -0600
Received: from 95991385052 named unknown by gmailapi.google.com with HTTPREST;
 Fri, 6 Mar 2026 13:25:17 -0600
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20260306150613.350029-1-arnd@kernel.org>
References: <20260306150613.350029-1-arnd@kernel.org>
MIME-Version: 1.0
Date: Fri, 6 Mar 2026 13:25:17 -0600
X-Gm-Features: AaiRm51im8Opzhh4FrDhukBOYJIJAUVnJyGocvgFTBcd1zQhrlQ-HbSj120EYv0
Message-ID: <CAPAsAGzSybyM_GsP1JxzZTj=SFeN6K8t9uQ3XAXBWiN+019Wmw@mail.gmail.com>
Subject: Re: [PATCH] ubsan: turn off kmsan inside of ubsan instrumentation
To: Arnd Bergmann <arnd@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Nathan Chancellor <nathan@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>, Kees Cook <kees@kernel.org>, Marco Elver <elver@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com, 
	linux-hardening@vger.kernel.org, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, "Peter Zijlstra (Intel)" <peterz@infradead.org>, 
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=D+1k+Tew;       arc=pass
 (i=1);       spf=pass (google.com: domain of ryabinin.a.a@gmail.com
 designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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
X-Rspamd-Queue-Id: B39F0227085
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[gmail.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBCSL7B6LWYHBBH6UVTGQMGQEMTSTAIA];
	RCVD_TLS_LAST(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[arndb.de,kernel.org,google.com,gmail.com,googlegroups.com,vger.kernel.org,infradead.org,lists.linux.dev];
	FREEMAIL_FROM(0.00)[gmail.com];
	RCPT_COUNT_TWELVE(0.00)[15];
	FROM_HAS_DN(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	NEURAL_HAM(-0.00)[-0.978];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[ryabininaa@gmail.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	MID_RHS_MATCH_FROMTLD(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev,lkml];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,mail-yx1-xb13c.google.com:rdns,mail-yx1-xb13c.google.com:helo,googlegroups.com:dkim,googlegroups.com:email,arndb.de:email]
X-Rspamd-Action: no action

Arnd Bergmann <arnd@kernel.org> writes:

> From: Arnd Bergmann <arnd@arndb.de>
>
> The structure initialization in the two type mismatch handling functions
> causes a call to __msan_memset() to be generated inside of a UACCESS
> block, which in turn leads to an objtool warning about possibly leaking
> uaccess-enabled state:
>
> lib/ubsan.o: warning: objtool: __ubsan_handle_type_mismatch+0xda: call to __msan_memset() with UACCESS enabled
> lib/ubsan.o: warning: objtool: __ubsan_handle_type_mismatch_v1+0xf4: call to __msan_memset() with UACCESS enabled
>
> Most likely __msan_memset() is safe to be called here and could be added
> to the uaccess_safe_builtin[] list of safe functions, but seeing that
> the ubsan file itself already has kasan, ubsan and kcsan disabled itself,
> it is probably a good idea to also turn off kmsan here, in particular this
> also avoids the risk of recursing between ubsan and kcsan checks in
> other functions of this file.
>
> I saw this happen while testing randconfig builds with clang-22, but did
> not try older versions, or attempt to see which kernel change introduced
> the warning.
>
> Cc: Kees Cook <kees@kernel.org>
> Cc: Marco Elver <elver@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: kasan-dev@googlegroups.com
> Cc: linux-hardening@vger.kernel.org
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> ---
>  lib/Makefile | 1 +
>  1 file changed, 1 insertion(+)
>

Acked-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAPAsAGzSybyM_GsP1JxzZTj%3DSFeN6K8t9uQ3XAXBWiN%2B019Wmw%40mail.gmail.com.
