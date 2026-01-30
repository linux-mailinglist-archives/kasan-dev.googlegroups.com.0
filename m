Return-Path: <kasan-dev+bncBC6OLHHDVUOBBUG56HFQMGQELAEEWKY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id KMv6JdJufGkSMgIAu9opvQ
	(envelope-from <kasan-dev+bncBC6OLHHDVUOBBUG56HFQMGQELAEEWKY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Jan 2026 09:41:54 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A2A0B8844
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Jan 2026 09:41:54 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-38305d006fesf9810921fa.2
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Jan 2026 00:41:54 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769762513; cv=pass;
        d=google.com; s=arc-20240605;
        b=gw+4RbLQZOrqi5cM2FyrVWR2wq5eJhqQPosCZ19gCXgqSMM0RmJHJeTPGhUQaEQK3q
         hWdvPVERyGgYnyKaL8uVMMqWAQGOgCJ3mvnRHoIo6NDib2Q9VWCcKvVF4gLrlSRbnRGA
         OzMNyXnueQ55Y3yUNK21G6RwYrlKpKrOKp16RJ6DiQ8ic7G+oh5OOV1N+XdfM80qH3rE
         w5GV03z/Y3A5z8iymZqtggkU/27O4Yq7oCPZndDNEZgyXITyF6gg/wqjT9TpmVdsoCQF
         jUrlgbC8XHNQpWcj5uTtqm19GkUux6YUoGZYtkZpFeE64ORlGweFgK5h69wpgytoZDQn
         S2Tg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=MkND8aNRd1US915rla6jdwRlSq3J/2xabZ6X1wIOXzE=;
        fh=bxGEv50yxIswl/wPDBOBICEhexguNdMA42K5iNrlQdQ=;
        b=cpFB36zxgtcBiSvK7MxI3sJWcawBsPeLd0ULxgt9OSrQFMUUCPSqLCmWePwv7n0Hmq
         cXxaeu0ci6WxxxSg05tLGO9VW5NoZ0NfEfPt6Y9x82LuTQ5ElIhVxLcgbCDCmVRFLE1P
         zIT5bkywyz7bDLvp7DAkZoPWZ9iSHC+DBtSrUKGG8FyAsqNlHsa5e64FxzohRSmfAzK8
         iGVay2FluiHjolAIpr63F7XR5KqAtt1eOickGyo/w0pk2BI6P2Nfapo3AcoJamnov4BM
         EYcmzEOEqDAnyv7WvY1PGZFHmaJMvSd7mnuGxgdWNwsfFqj+D+F2DPGJgWyYfVTnaB19
         TYkQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yy2+AOwQ;
       arc=pass (i=1);
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769762513; x=1770367313; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MkND8aNRd1US915rla6jdwRlSq3J/2xabZ6X1wIOXzE=;
        b=q2dsDUK6a+Ouclhs4/FMk2oTYjrwx3eHn8dBdcMsJRI72O7I266Uugm2hDaf/+oLS/
         JQkdMk7fAp18M51C6tDYF61CS2aQMva6O4iExP+aHpt1Q7AxxsJoT0S8T1QSeBEJDnkC
         sJ1EOZnSGgz5ue56uHRcrWaCJldddRqbM/L7HMb15Ec99tWaEKH4drng9zBachdPKjeM
         gPytdfoEMXhVd7NHO0kTd1rbN/aG0xdxnSDzVNZjumPE0S4EebtZhb6pjkkadclu3VNK
         cf1twQh51fWFyioejQcMoqNu7PZYjRpq4EMyjFyEBvvnGDmp9aep/xQOK9hQuga0GHdS
         2uoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769762513; x=1770367313;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MkND8aNRd1US915rla6jdwRlSq3J/2xabZ6X1wIOXzE=;
        b=trQeRoIjYIyYeuKcddqnVOoqq9/ZBVzHNiu740vVkBLUbvJB7lCbpRtPiZJ6LRTxSe
         5HexhutxoYw0UaWpjIO9/cH27JI5oIp6BF9XCjEXRDP+7l/2lXafAXikNsuQQULwQYVp
         es/GmhFIleYegYf8ovDxnMOzlPyxI0XgXK3vWvzIuG5K5Z2IrtJjkFlVq0q9iLjJ+OIM
         VfRbShRYV/tZ77gQ7etFKxnmF6L7fXScNv7hbJnkt53Q26pS+a0dIsDChYcYWPKhdIjn
         o0M03dKOF/3bVxcVuZ0oblTn49jLKn/OQXpx7iJEK4gcVNnqcdRlKOGsatjBhcKI8AjS
         ohRA==
X-Forwarded-Encrypted: i=3; AJvYcCV4zoOs3atPpJ1C50eYYGSo7fkqKkM/zKTQSOsEI5j0ikTTiK3JGpABNGl5rrSF3VHSWNfdhw==@lfdr.de
X-Gm-Message-State: AOJu0YzojpzGj90ywL4ntbFrlPgRF321KtAYRrYVCYiFdNSSsymIEjxS
	PELI2de7msbHEI/hTI3gYPD4kXU2wL9df1uCYJlgT2sTwUsp2kVf32L5
X-Received: by 2002:a2e:b8cb:0:b0:37a:5cb7:968f with SMTP id 38308e7fff4ca-3864669a304mr7681681fa.29.1769762512869;
        Fri, 30 Jan 2026 00:41:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FM5U56pT+jVS6XY4ZGGeKAZz49IC9573sFTbQ9mQQguw=="
Received: by 2002:a2e:9157:0:b0:382:5b25:632c with SMTP id 38308e7fff4ca-38637f3f26bls2408261fa.0.-pod-prod-07-eu;
 Fri, 30 Jan 2026 00:41:49 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWZrJak9faIsm7UzeNhc8vABYOMmVMJ479gKT4aeS4v9Gb7H0wsjYJb77qw19MBWfKZG5z6TPYgoEU=@googlegroups.com
X-Received: by 2002:a2e:be1b:0:b0:37f:d911:5941 with SMTP id 38308e7fff4ca-3864662d63emr6333751fa.21.1769762509586;
        Fri, 30 Jan 2026 00:41:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769762509; cv=pass;
        d=google.com; s=arc-20240605;
        b=L6ZYfqd09Nf8Xp/oZQOFt32QYVH3yL9rPDcZkE/Ib1a0/CfnIXaJzhUljx0sIynKBT
         CDWR4dUmCRogwn34XDDlP+QsX6mqQVd3tCxRiAsaYxmpx3UYV5P9EcuZuhHJeckkEUea
         rI4Nk43TC/DX4eLF0eSZ9BWEhAY/6jwNDAk9pX462ENk1XmSS7o9S/e0C/OFqWW4+QMT
         DSKGjp/y/l4hYAZKvILoN7V1qnhHeexZm6UJz+OX9YI4eO41mvX4Jxsy43p2+CY4Kqdc
         TtKw7Ej7HPyY3qMc7YIp/bYFO3+FUURqyXR7dHVCvtBJG8sRkkwDPKjVT0Yb9XPTIGaZ
         oe3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dZL+J6+xF9GI8RWa5jigor7E2uAI4Jx8M1Vcygno4Nc=;
        fh=HJODpd1O7RyI3EhJOIxStzyyhr6TWyCs8AZi8eJDW7M=;
        b=OSBIVDIlLZu2WeRi8rtiu/BVJRy7a6MMtm+j7NTIQGhgbIhi5c5jlg+mUxwxHc98K9
         RIN35iL6uek1eFLU5B1IX3w3tCiNq8tXj4f/bTVx3hUbFaH+R66L8o/N0t3GDGNVNiXp
         tfHzFsbZ0N7N4OJPC8MxbqPJ3UIzwbB4eOz7CsPyVaMCGnPWa+poVJ0kQsaB6nXrWKgM
         44prt5UKoOkOpqK6lzxcGso2lJy3kE0Zva+ub8+4+IaKGH71cAhe8/J5/U+vzdEesdki
         ltA7agGw41qm6W3Dfd3OQaalrSIukYQshxVKi9/UZ7HKbtefCCqSLIDguAwQcNhvaSCI
         hfzg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yy2+AOwQ;
       arc=pass (i=1);
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38625c5e81bsi1590261fa.1.2026.01.30.00.41.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Jan 2026 00:41:49 -0800 (PST)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id ffacd0b85a97d-4359a316d89so1474404f8f.0
        for <kasan-dev@googlegroups.com>; Fri, 30 Jan 2026 00:41:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769762509; cv=none;
        d=google.com; s=arc-20240605;
        b=b0yoBqg3INQ8xOqNWVGXwlXxvjX0ycZEGvlAewTTELYP+n7CPFqIzfLwOffoNE7VFe
         Vmt5WARU2nV6uHhWkxNZZgQMSQ5vm3Hd9DF+PQaBhW8WrFlY99bPTUu6CoaOP8Do32a2
         CGcBhWtLdMeNO/jcVzTRoveC9ToECvO7iMYR+C8lIcbNCmmQndZjZXTLqSD/KTa+qbwh
         CqMNYwee5tDtde7Uny5FxiT1AdWE6TEbSR3fKw9GJm6enXV79VrtknM+bZW9vo3bxoDw
         o67WiJ/WlhNAmdjD3lbiDlq2ma8KtXVoV5ia6qNCwrPzNqpgNAhr3ZtwVp352lUgyTdQ
         4cvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dZL+J6+xF9GI8RWa5jigor7E2uAI4Jx8M1Vcygno4Nc=;
        fh=HJODpd1O7RyI3EhJOIxStzyyhr6TWyCs8AZi8eJDW7M=;
        b=DC3mzYPitAt/+Zz1IdPExH27SQah26VVDQpbLkPps9IwZ6M6KAQPQvLGOUxTVGVuE4
         u3y5smdhpbREKE4MAhLvaYQJwtWXOw8ZYjd8EnNG9XfAKBLh5gnYcZY1Wc4FjJwkxX+k
         lDmnLWWCh6csV8kH+jJJbBTFqMLVBUVAy0itNSZSkSIRskmhcicbIyZ7ODzgRdgo1juB
         QlH/3zKLeYQ8YME5IUY77MlZLvLz5eHa30QsqH4BMJoGVt4yl+1klgRk92ZQJ9d9s+BR
         PO1FM7hRGKGpEV/tpOzijG8KXUUCWfoRexh1jG/ts7YnTqAze07MoSutR5uuX3qvPvVw
         GM0g==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCUp+l9zeWInTWDLxQwG70c1cb55mfn9IrUP1QSKHBy6XEs5a4jUqLapqWAw5EbiskOhRlIclud23v0=@googlegroups.com
X-Gm-Gg: AZuq6aIWDxjLmdX58hBtNo1pO8BWfiEDJ7EuNtVhbTBz8FCMneilrRk4+nrVv5blvVU
	yZuRMnLE4Kx+bTHLAa/m/lTxbH2sxKvhKPoYqdt2hNwRw2NdY29OuQKdWV82xOik9RIbY7NS5IF
	KOukH6K0xd3kKJwSOLCEM8jIJta8WjYYKZXJO4er9MtBxZapGrIQKyAaluE/VUunf1WFiwiChIV
	Re61JKRuqWliBqo5k13R84FFXD1fo0QbnG+gnmsbCekEWPQ7bhPjOs5v0FFgUpHzpCd1w==
X-Received: by 2002:a05:6000:4007:b0:435:a2f8:1515 with SMTP id
 ffacd0b85a97d-435f3a62efamr3285444f8f.10.1769762508484; Fri, 30 Jan 2026
 00:41:48 -0800 (PST)
MIME-Version: 1.0
References: <20260123073916.956498-1-mkchauras@linux.ibm.com>
In-Reply-To: <20260123073916.956498-1-mkchauras@linux.ibm.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Jan 2026 16:41:36 +0800
X-Gm-Features: AZwV_QhyRvW1YTL7t6hK5HsBTRNnJfnMIpMe6PWoXpn4YBgsHcUOCZVRIGxOSCA
Message-ID: <CABVgOSkkS5vU0AJ-8xZgdebjdaPjBnVDBA2rUSzBmkxjRVMQww@mail.gmail.com>
Subject: Re: [PATCH v4 0/8] Generic IRQ entry/exit support for powerpc
To: Mukesh Kumar Chaurasiya <mkchauras@linux.ibm.com>
Cc: maddy@linux.ibm.com, mpe@ellerman.id.au, npiggin@gmail.com, 
	chleroy@kernel.org, ryabinin.a.a@gmail.com, glider@google.com, 
	andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com, 
	oleg@redhat.com, kees@kernel.org, luto@amacapital.net, wad@chromium.org, 
	mchauras@linux.ibm.com, thuth@redhat.com, ruanjinjie@huawei.com, 
	sshegde@linux.ibm.com, akpm@linux-foundation.org, charlie@rivosinc.com, 
	deller@gmx.de, ldv@strace.io, macro@orcam.me.uk, segher@kernel.crashing.org, 
	peterz@infradead.org, bigeasy@linutronix.de, namcao@linutronix.de, 
	tglx@linutronix.de, mark.barnett@arm.com, linuxppc-dev@lists.ozlabs.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="000000000000b1f1c4064996f1e7"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=yy2+AOwQ;       arc=pass
 (i=1);       spf=pass (google.com: domain of davidgow@google.com designates
 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.81 / 15.00];
	SIGNED_SMIME(-2.00)[];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.20)[multipart/signed,text/plain];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC6OLHHDVUOBBUG56HFQMGQELAEEWKY];
	RCVD_COUNT_THREE(0.00)[4];
	FREEMAIL_CC(0.00)[linux.ibm.com,ellerman.id.au,gmail.com,kernel.org,google.com,arm.com,redhat.com,amacapital.net,chromium.org,huawei.com,linux-foundation.org,rivosinc.com,gmx.de,strace.io,orcam.me.uk,kernel.crashing.org,infradead.org,linutronix.de,lists.ozlabs.org,vger.kernel.org,googlegroups.com];
	RCPT_COUNT_TWELVE(0.00)[32];
	MIME_TRACE(0.00)[0:+,1:+,2:~];
	TO_DN_SOME(0.00)[];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	HAS_REPLYTO(0.00)[davidgow@google.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_ATTACHMENT(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail.gmail.com:mid]
X-Rspamd-Queue-Id: 3A2A0B8844
X-Rspamd-Action: no action

--000000000000b1f1c4064996f1e7
Content-Type: text/plain; charset="UTF-8"

On Fri, 23 Jan 2026 at 15:39, Mukesh Kumar Chaurasiya
<mkchauras@linux.ibm.com> wrote:
>
> Adding support for the generic irq entry/exit handling for PowerPC. The
> goal is to bring PowerPC in line with other architectures that already
> use the common irq entry infrastructure, reducing duplicated code and
> making it easier to share future changes in entry/exit paths.
>
> This is slightly tested of ppc64le and ppc32.
>
> The performance benchmarks are below:
>
> perf bench syscall usec/op (-ve is improvement)
>
> | Syscall | Base        | test        | change % |
> | ------- | ----------- | ----------- | -------- |
> | basic   | 0.093543    | 0.093023    | -0.56    |
> | execve  | 446.557781  | 450.107172  | +0.79    |
> | fork    | 1142.204391 | 1156.377214 | +1.24    |
> | getpgid | 0.097666    | 0.092677    | -5.11    |
>
> perf bench syscall ops/sec (+ve is improvement)
>
> | Syscall | Base     | New      | change % |
> | ------- | -------- | -------- | -------- |
> | basic   | 10690548 | 10750140 | +0.56    |
> | execve  | 2239     | 2221     | -0.80    |
> | fork    | 875      | 864      | -1.26    |
> | getpgid | 10239026 | 10790324 | +5.38    |
>
>
> IPI latency benchmark (-ve is improvement)
>
> | Metric         | Base (ns)     | New (ns)      | % Change |
> | -------------- | ------------- | ------------- | -------- |
> | Dry run        | 583136.56     | 584136.35     | 0.17%    |
> | Self IPI       | 4167393.42    | 4149093.90    | -0.44%   |
> | Normal IPI     | 61769347.82   | 61753728.39   | -0.03%   |
> | Broadcast IPI  | 2235584825.02 | 2227521401.45 | -0.36%   |
> | Broadcast lock | 2164964433.31 | 2125658641.76 | -1.82%   |
>
>
> Thats very close to performance earlier with arch specific handling.
>
> Tests done:
>  - Build and boot on ppc64le pseries.
>  - Build and boot on ppc64le powernv8 powernv9 powernv10.
>  - Build and boot on ppc32.
>  - Performance benchmark done with perf syscall basic on pseries.
>

Passes the irq_test_cases KUnit suite on (qemu) powerpc(64),
powerpcle, and powerpc32 targets.

./tools/testing/kunit/kunit.py run --arch powerpc  irq_test_cases
./tools/testing/kunit/kunit.py run --arch powerpcle  irq_test_cases
./tools/testing/kunit/kunit.py run --arch powerpc32  irq_test_cases

Tested-by: David Gow <davidgow@google.com>

Cheers,
-- David

> Changelog:
> V3 -> V4
>  - Fixed the issue in older gcc version where linker couldn't find
>    mem functions
>  - Merged IRQ enable and syscall enable into a single patch
>  - Cleanup for unused functions done in separate patch.
>  - Some other cosmetic changes
> V3: https://lore.kernel.org/all/20251229045416.3193779-1-mkchauras@linux.ibm.com/
>
> V2 -> V3
>  - #ifdef CONFIG_GENERIC_IRQ_ENTRY removed from unnecessary places
>  - Some functions made __always_inline
>  - pt_regs padding changed to match 16byte interrupt stack alignment
>  - And some cosmetic changes from reviews from earlier patch
> V2: https://lore.kernel.org/all/20251214130245.43664-1-mkchauras@linux.ibm.com/
>
> V1 -> V2
>  - Fix an issue where context tracking was showing warnings for
>    incorrect context
> V1: https://lore.kernel.org/all/20251102115358.1744304-1-mkchauras@linux.ibm.com/
>
> RFC -> PATCH V1
>  - Fix for ppc32 spitting out kuap lock warnings.
>  - ppc64le powernv8 crash fix.
>  - Review comments incorporated from previous RFC.
> RFC https://lore.kernel.org/all/20250908210235.137300-2-mchauras@linux.ibm.com/
>
> Mukesh Kumar Chaurasiya (8):
>   powerpc: rename arch_irq_disabled_regs
>   powerpc: Prepare to build with generic entry/exit framework
>   powerpc: introduce arch_enter_from_user_mode
>   powerpc: Introduce syscall exit arch functions
>   powerpc: add exit_flags field in pt_regs
>   powerpc: Prepare for IRQ entry exit
>   powerpc: Enable GENERIC_ENTRY feature
>   powerpc: Remove unused functions
>
>  arch/powerpc/Kconfig                    |   1 +
>  arch/powerpc/include/asm/entry-common.h | 533 ++++++++++++++++++++++++
>  arch/powerpc/include/asm/hw_irq.h       |   4 +-
>  arch/powerpc/include/asm/interrupt.h    | 386 +++--------------
>  arch/powerpc/include/asm/kasan.h        |  15 +-
>  arch/powerpc/include/asm/ptrace.h       |   6 +-
>  arch/powerpc/include/asm/signal.h       |   1 -
>  arch/powerpc/include/asm/stacktrace.h   |   6 +
>  arch/powerpc/include/asm/syscall.h      |   5 +
>  arch/powerpc/include/asm/thread_info.h  |   1 +
>  arch/powerpc/include/uapi/asm/ptrace.h  |  14 +-
>  arch/powerpc/kernel/interrupt.c         | 254 ++---------
>  arch/powerpc/kernel/ptrace/ptrace.c     | 142 +------
>  arch/powerpc/kernel/signal.c            |  25 +-
>  arch/powerpc/kernel/syscall.c           | 119 +-----
>  arch/powerpc/kernel/traps.c             |   2 +-
>  arch/powerpc/kernel/watchdog.c          |   2 +-
>  arch/powerpc/perf/core-book3s.c         |   2 +-
>  18 files changed, 690 insertions(+), 828 deletions(-)
>  create mode 100644 arch/powerpc/include/asm/entry-common.h
>
> --
> 2.52.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123073916.956498-1-mkchauras%40linux.ibm.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSkkS5vU0AJ-8xZgdebjdaPjBnVDBA2rUSzBmkxjRVMQww%40mail.gmail.com.

--000000000000b1f1c4064996f1e7
Content-Type: application/pkcs7-signature; name="smime.p7s"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="smime.p7s"
Content-Description: S/MIME Cryptographic Signature

MIIUnQYJKoZIhvcNAQcCoIIUjjCCFIoCAQExDzANBglghkgBZQMEAgEFADALBgkqhkiG9w0BBwGg
ghIEMIIGkTCCBHmgAwIBAgIQfofDAVIq0iZG5Ok+mZCT2TANBgkqhkiG9w0BAQwFADBMMSAwHgYD
VQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
AxMKR2xvYmFsU2lnbjAeFw0yMzA0MTkwMzUzNDdaFw0zMjA0MTkwMDAwMDBaMFQxCzAJBgNVBAYT
AkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSowKAYDVQQDEyFHbG9iYWxTaWduIEF0bGFz
IFI2IFNNSU1FIENBIDIwMjMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDYydcdmKyg
4IBqVjT4XMf6SR2Ix+1ChW2efX6LpapgGIl63csmTdJQw8EcbwU9C691spkltzTASK2Ayi4aeosB
mk63SPrdVjJNNTkSbTowej3xVVGnYwAjZ6/qcrIgRUNtd/mbtG7j9W80JoP6o2Szu6/mdjb/yxRM
KaCDlloE9vID2jSNB5qOGkKKvN0x6I5e/B1Y6tidYDHemkW4Qv9mfE3xtDAoe5ygUvKA4KHQTOIy
VQEFpd/ZAu1yvrEeA/egkcmdJs6o47sxfo9p/fGNsLm/TOOZg5aj5RHJbZlc0zQ3yZt1wh+NEe3x
ewU5ZoFnETCjjTKz16eJ5RE21EmnCtLb3kU1s+t/L0RUU3XUAzMeBVYBEsEmNnbo1UiiuwUZBWiJ
vMBxd9LeIodDzz3ULIN5Q84oYBOeWGI2ILvplRe9Fx/WBjHhl9rJgAXs2h9dAMVeEYIYkvW+9mpt
BIU9cXUiO0bky1lumSRRg11fOgRzIJQsphStaOq5OPTb3pBiNpwWvYpvv5kCG2X58GfdR8SWA+fm
OLXHcb5lRljrS4rT9MROG/QkZgNtoFLBo/r7qANrtlyAwPx5zPsQSwG9r8SFdgMTHnA2eWCZPOmN
1Tt4xU4v9mQIHNqQBuNJLjlxvalUOdTRgw21OJAFt6Ncx5j/20Qw9FECnP+B3EPVmQIDAQABo4IB
ZTCCAWEwDgYDVR0PAQH/BAQDAgGGMDMGA1UdJQQsMCoGCCsGAQUFBwMCBggrBgEFBQcDBAYJKwYB
BAGCNxUGBgkrBgEEAYI3FQUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUM7q+o9Q5TSoZ
18hmkmiB/cHGycYwHwYDVR0jBBgwFoAUrmwFo5MT4qLn4tcc1sfwf8hnU6AwewYIKwYBBQUHAQEE
bzBtMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDsGCCsG
AQUFBzAChi9odHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9yb290LXI2LmNydDA2
BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3QtcjYuY3JsMBEG
A1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAgEAVc4mpSLg9A6QpSq1JNO6tURZ4rBI
MkwhqdLrEsKs8z40RyxMURo+B2ZljZmFLcEVxyNt7zwpZ2IDfk4URESmfDTiy95jf856Hcwzdxfy
jdwx0k7n4/0WK9ElybN4J95sgeGRcqd4pji6171bREVt0UlHrIRkftIMFK1bzU0dgpgLMu+ykJSE
0Bog41D9T6Swl2RTuKYYO4UAl9nSjWN6CVP8rZQotJv8Kl2llpe83n6ULzNfe2QT67IB5sJdsrNk
jIxSwaWjOUNddWvCk/b5qsVUROOuctPyYnAFTU5KY5qhyuiFTvvVlOMArFkStNlVKIufop5EQh6p
jqDGT6rp4ANDoEWbHKd4mwrMtvrh51/8UzaJrLzj3GjdkJ/sPWkDbn+AIt6lrO8hbYSD8L7RQDqK
C28FheVr4ynpkrWkT7Rl6npWhyumaCbjR+8bo9gs7rto9SPDhWhgPSR9R1//WF3mdHt8SKERhvtd
NFkE3zf36V9Vnu0EO1ay2n5imrOfLkOVF3vtAjleJnesM/R7v5tMS0tWoIr39KaQNURwI//WVuR+
zjqIQVx5s7Ta1GgEL56z0C5GJoNE1LvGXnQDyvDO6QeJVThFNgwkossyvmMAaPOJYnYCrYXiXXle
A6TpL63Gu8foNftUO0T83JbV/e6J8iCOnGZwZDrubOtYn1QwggWDMIIDa6ADAgECAg5F5rsDgzPD
hWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBS
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
Dxz3AgMBAAGjggHgMIIB3DAeBgNVHREEFzAVgRNkYXZpZGdvd0Bnb29nbGUuY29tMA4GA1UdDwEB
/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDBAYIKwYBBQUHAwIwHQYDVR0OBBYEFHZtY3XkWtC2
e2Idfk+0JyK7BLzzMFgGA1UdIARRME8wCQYHZ4EMAQUBAjBCBgorBgEEAaAyCgMDMDQwMgYIKwYB
BQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAwGA1UdEwEB/wQC
MAAwgZoGCCsGAQUFBwEBBIGNMIGKMD4GCCsGAQUFBzABhjJodHRwOi8vb2NzcC5nbG9iYWxzaWdu
LmNvbS9jYS9nc2F0bGFzcjZzbWltZWNhMjAyMzBIBggrBgEFBQcwAoY8aHR0cDovL3NlY3VyZS5n
bG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NhdGxhc3I2c21pbWVjYTIwMjMuY3J0MB8GA1UdIwQYMBaA
FDO6vqPUOU0qGdfIZpJogf3BxsnGMEYGA1UdHwQ/MD0wO6A5oDeGNWh0dHA6Ly9jcmwuZ2xvYmFs
c2lnbi5jb20vY2EvZ3NhdGxhc3I2c21pbWVjYTIwMjMuY3JsMA0GCSqGSIb3DQEBCwUAA4ICAQBo
hqjbVaHxZoT6HHUuwQcTlbgXpuVi59bQPrSwb/6Pn1t3h3SLeuUCvOYpoQjxlWy/FexsPW+nWS0I
PUmWpt6sxbIRTKPfb7cPk32XezfnA0jexucybiXzkZKTrbI7zoMOzDIWpTKYZAonB9Zzi7Dso4An
ZOtz/E3yhdR/q1MK30d5fiCS0vorEd0Oy8Jzcc7TJ2HGMzEEXiFFvVrJYJHvfYOeXE4ywAG6YWO0
x78+bXeB9vkeWHhOYKyYXuAXrnHASddEICg1QlJCHDAISMC1Wn/tjqTMTt3sDAe+dhi9V1FEGTbG
g9PxPVP4huJEMIBu/MWNMzHfiW4E7eCHVPrmtX7CFDlMik7qsgQBbO5h6EcxBamhIflfMgoISsRJ
Vyll2E5BNVwkNstMgU3WMg5yIaQcuGFgFnMTrQcaLEEFPV3cCP9pgXovYDirnB7FKNdCZNHfeBY1
HEXJ2jIPDP6nWSbYoRry0TvPgxh5ZeM5+sc1L7kY75C8U4FV3t4qdC+p7rgqfAggdvDPa5BJbTRg
KAzwyf3z7XUrYp38pXybmDnsEcRNBIOEqBXoiBxZXaKQqaY921nWAroMM/6I6CVpTnu6JEeQkoi4
IgGIEaTFPcgAjvpDQ8waLJL84EP6rbLW6dop+97BXbeO9L/fFf40kBhve6IggpJSeU9RdCQ5czGC
Al0wggJZAgEBMGgwVDELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKjAo
BgNVBAMTIUdsb2JhbFNpZ24gQXRsYXMgUjYgU01JTUUgQ0EgMjAyMwIQAYQLf/BIzLow9kWqD8My
PzANBglghkgBZQMEAgEFAKCBxzAvBgkqhkiG9w0BCQQxIgQgODfHES73TzkasZ+vqr8fZhjjS9Xr
ecEGJcMV1nyHrD8wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYw
MTMwMDg0MTQ5WjBcBgkqhkiG9w0BCQ8xTzBNMAsGCWCGSAFlAwQBKjALBglghkgBZQMEARYwCwYJ
YIZIAWUDBAECMAoGCCqGSIb3DQMHMAsGCSqGSIb3DQEBBzALBglghkgBZQMEAgEwDQYJKoZIhvcN
AQEBBQAEggEAKFxxTWR2iRbVXKjUTI1DMX6nOIJMi7NXfIfqiwLsGkQhPl9TMhC/z6LqxFZ0JBBp
NvwLlLPWExKdpU8x1d7CFv1IU5PexMxyXDjKXrMJK9wL727lWdEln77mVy/duQpMPXxTQeG70fTZ
c/BJSLZIIOSuON9kEoZUrLdGyNoHPXEM1UL7YBGG5krObWvfnc1fNPnEUbJKLG2msH6NhOAcDEkr
yQOxkInfnGBpZpMyYca0gmKW0+DCozT09iwGfo6YhaoznnC5AlRPoTg5EwuTAhAYIuT8SDuV89qu
JL1Q+jmz0heXMSYdLeqbKlP2mXTtQf69z6aixCXzw18eWIGRgA==
--000000000000b1f1c4064996f1e7--
