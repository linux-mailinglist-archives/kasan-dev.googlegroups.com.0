Return-Path: <kasan-dev+bncBDJPLAN63YNBBM6EVLGQMGQETCHMZGQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id IIeZGTaiqmlLUgEAu9opvQ
	(envelope-from <kasan-dev+bncBDJPLAN63YNBBM6EVLGQMGQETCHMZGQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2026 10:45:26 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id E0D3621E295
	for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2026 10:45:25 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-824b3532298sf3510215b3a.0
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2026 01:45:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772790323; cv=pass;
        d=google.com; s=arc-20240605;
        b=QOHQeN3Gpg+zzVgWRp8ps4HHblaIgarGDw9kUGMUCUH0A6TIowEK/cuwRik6Im+VQL
         nOsEAIV3ZbydcvkIMzZUeWY9gT0RqT9rObVKB7ZI+G8ZytmcGCefq4iW+uXhAMVNGW8R
         nOjgSN3V/FQp8BP8nXsHG/AyIX6S29xo9IwxM/fPRDdLz5Kq2rysLmq1dlxJv7skpi+u
         yNodJp0K39QmEt+J8fkxLYlJTarIIjgYA5/kOKqjeAJfulMVPKbsvDaXZA4YZx7TUwEN
         Dad6dnT/pA7m49R7Hs/3J9SkWuy6EZsc0nCREUU09+3zC6RYQJiEUW9phf0yRspSbxWI
         cRng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=TsoXXUguI7ycs9n6FMl2OBLoSypjy46m9q2c5TLbc7w=;
        fh=ySOG1Q7LcYYzCi9nyX6iASwY5In5yeMcq4rZjVp7ikA=;
        b=TwAOxVZeAjV0llyq3dYjt7kK2zWEseNITU8KCm5hoPW791At01qg/6EuusmFmX7Uq6
         fvRf578Wu1Hu9gpGRzJWif2ZdZ8J76c+gtVE4pL3KMmvlTFmOfT3QVhT0f0C7NfQp0ll
         RQIxRVrsWdDcekJq+7pDezDNMDDCj3YRmMMO2pD657as5CDpP2MiiJSbkBpLKkP0EqG2
         gHBn/u0vRnq5SjTvvX20jlaB9BILFRujxfpPwZFRI5NMY9J8CfhX4yDVx7w0QTPSrOI5
         +XOxyfryum0qteTa4XifKUzYSOLbCQ00yWLbTFrIrSNlY5GUuRvQmV+fKaFZSfyQApzp
         YrPw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=m5E8t8nR;
       spf=pass (google.com: domain of jiakaipeanut@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=jiakaipeanut@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772790323; x=1773395123; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TsoXXUguI7ycs9n6FMl2OBLoSypjy46m9q2c5TLbc7w=;
        b=KH7dXVDNcQItoQj9N/tgATNLMd6GeLSan9tE5u9ko2tjunIGvfzPojWK+2OVWZVDrL
         IMmUKMcWScnt8EIPTHeDNRVYbCq5rw8QRUyTQhlNbpORuexpd6PsCJh1Dzpt4huySCRp
         8YlpE2On7wXvNK9yp/JwJ0uHyyC4777KJA/LuRMnUW6Tf0XNPMAe1wnOL6KT78KbLZ8i
         PxTyjWVLQB5rS9Flyg9gEy5fMAcWcg9XVD4SETWONLSM11KjZrrXvewCvhn6UszEmLCn
         w3Q2JOkcexd06rTVN6AopICZkZQIiLrgGVg39HiV+/7Qrtn0TwfUT0LchtryRR6gyL9E
         Thow==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1772790323; x=1773395123; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=TsoXXUguI7ycs9n6FMl2OBLoSypjy46m9q2c5TLbc7w=;
        b=VQFiSuabw7/dd2v/EpCC80M3zPjhSEyPIUAOZkpSKLj4mSvW/3kZUDnW+VkLgmrDqo
         6qdiAdV1AuNEWM6aZUUOkfsA9DIRd7BWlS7uyg+mbo6NiTqEtGHtdTyU+cpzXpYeVDAL
         XZxrmva+yK4tuKWfZSHVaVyksvamd+4/r58CpF2pbnCtGtiwUjP5A70EMGUUAUcR3wbj
         AaVqxGL5lIyHE3gvMk36P1ETJmR+D+UDk082GsB2+0h57P1rGwOtswWrssVo0H0cIFb9
         q4CfarEUcOL1+9CZuQQ2oE4zBlF47tmoPggnK4kyhzTo4NCuRRvEf2utvGQzQlsk4htS
         prgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772790323; x=1773395123;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TsoXXUguI7ycs9n6FMl2OBLoSypjy46m9q2c5TLbc7w=;
        b=U10SmRsUeR70mioGed31wSZmblA7eDnkwtgXwHeQpnxB685XXiEuwr+Ft508hdRhak
         zzb3ale4wI7B6ZjfNjJxP21aANF0Y3011W1NzssSqGtcdxPP98GQmYUb+sjij2/+lFeW
         TG3gmYTV+Mq0r62tfQ7VN+Aw3DVorRUIgYXPIDJ9H4Yc9/XCucwJR6XvSZIIyVaO47sr
         7NtV2uBb93iEqsphWsU58aPWheH+YnbKucPdN0VHjcWoPlOP7i0lLoJQIGmo5Dtq3nS5
         F26kVXs3afYMAd+XEDp3qNu/p4DqmHRo4SOY9l+hNQaVyjO+gQ6Voa02OoaOm+Lwie/l
         7lJg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX/bK08ENTo48TahpM/oLJqhK6e/9oRrI7DsaIv25sjg2Qegg078bTpYn/w584hw2ZWH9uPvA==@lfdr.de
X-Gm-Message-State: AOJu0Yxhe3VV20yIhF3OfXPxw1++4HfnHUEDk/74RBef8U98CdjhhIHI
	v0imeIG3HC5UDD2Je3nLj0UGS7FvXOOqjGQifESbzkViJJu1MEhL2lTO
X-Received: by 2002:a05:6a00:90a2:b0:827:2ed6:888f with SMTP id d2e1a72fcca58-829a2f942c0mr1261059b3a.54.1772790323564;
        Fri, 06 Mar 2026 01:45:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FqazcKVv0GTi2TJ7LPM/x6SW14gxXXXdESA297bDcyuw=="
Received: by 2002:aa7:9f4e:0:b0:7f6:3f21:7d71 with SMTP id d2e1a72fcca58-82980cea714ls1586499b3a.1.-pod-prod-07-us;
 Fri, 06 Mar 2026 01:45:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVQoHrXxid1WvF/27eA9qEaQSrROklnz46XEY4zalBxzX4owjzW7DAMmFdbyiVGhLL6wxQbdjIc3ro=@googlegroups.com
X-Received: by 2002:a05:6a00:7598:b0:824:adf4:5a32 with SMTP id d2e1a72fcca58-829a2f4e0b9mr1211769b3a.42.1772790322226;
        Fri, 06 Mar 2026 01:45:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772790322; cv=none;
        d=google.com; s=arc-20240605;
        b=GB4OFSuTWUURAxJ398jrqElqBi/UJsnZiLZPt1vzH2mzXNXpat2Q+w7Fv1QLLfr9Lb
         RpJM+Kx3wII1dhiw+oDOfYCZP3/SR4P/RNFtDekPhqQJZVvxj/UYURqKjQ5vWPLycNcx
         kEAOr8cPqigR+6WT9ssfelCLVTRSdmHgUsjH+UJi8tEQ/rNG4CDUgElpZkiC1LNEHOMz
         TWYztMNDjRFgenhZmn2teGmLC1bvdNNqCJ2ZL1112S1RR+70OKIFJIiM7pBc3srugkXj
         uYXqvGNAMpYg0tJ/W+zJcnKlO/OVaHCL1Lr7vKrnzoYcvdjFV9eLwNThKhDopv/SINVg
         nOPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wS1qxKCchhjtDwRNXR6jv/SqzMa5hcVlBO3c/OsKvrQ=;
        fh=/25Yol+c2Akz/X/Epeiz3dd9lJdsgsFg5DtdW0aVivY=;
        b=HFq5Cu/Jz4ubdj+vA/piptvC3CPX4pxj181HmoMztjK+48LuFlE2YfPKfEdhnlB13i
         SlShLYr3SY28fuYXTL2tkr7HyU+GOZtwLuiMNLyiS5oKDkPytiQZPfZtD76Sz4BxJ4YN
         +PX5UiUG4IGT9Rip8PdjDm5QWINSHzOXQFdPfvGj1KK6OQF5fsnkB5Xw+EATRDxMEY/7
         hUbK/wKO8G3QXAywjhPc3H+AO9pd2ThcBMpSS3wFa5bEpByijBShn7I4w+xBbiM4SENv
         uruasLhKRN0mnuZd4UaVUwcRVEAi90Mz+A94ZmYL0rUGWhIhaVZoN1yeyHLxnp6rbJVo
         M6Ww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=m5E8t8nR;
       spf=pass (google.com: domain of jiakaipeanut@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=jiakaipeanut@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-829a48b2c35si28461b3a.4.2026.03.06.01.45.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Mar 2026 01:45:22 -0800 (PST)
Received-SPF: pass (google.com: domain of jiakaipeanut@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id d2e1a72fcca58-82976220e97so1585898b3a.3
        for <kasan-dev@googlegroups.com>; Fri, 06 Mar 2026 01:45:22 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVS5e/pe0GZoo3kouRCynny/VM5WsXspR88+SjPecO0IYaxXjEoP2EEezRe5iGxxOkK11U7P3J/Id4=@googlegroups.com
X-Gm-Gg: ATEYQzximbv0BXiFwVbw2FGbKAZoqvxMuCA6tdgpA+j6v6GQsGOV3/aS7mLhB+jeGr2
	biumW0fD2Z/1rq85DmQKRWGm2Mn3jo13FhiNB/KZvA3LAnnWqaAeEATFRPOp2Jfc9a4fCQm0EPT
	Whx1TzqyljWqhdpNJqwhpe5bgFhdzMuduycnUP/F/rrcObx2/IXrw4VF+nfjnn0EhSVrkHUSi2C
	D12iiAfkg8WJpXDTFRCIHRZd9AoeAE9m1/1JsNCVPCzX83cFnzi2RxhgarYirENe9EP3XPgIAN2
	gdo74GfjCQIADsl2VTA67t2Ey4mNJ5utfc7B5xBjcFJjKBQjOuU8UpjZABzvjc8DAh3KA3RRiXk
	U/599pvs1/9QJHcUIiPZvRYORMPaev7dup4X44873f4cWbE2cwn6/TyNKmRF5KseFfr0TtRwwpQ
	Ir/hv2TOZDfo8142jLyGX0oL2smoY7pQBzWicr7HBBuQf1
X-Received: by 2002:a05:6a21:a43:b0:393:c4d:be50 with SMTP id adf61e73a8af0-39858fda4a6mr1885603637.16.1772790321826;
        Fri, 06 Mar 2026 01:45:21 -0800 (PST)
Received: from localhost.localdomain ([210.73.43.101])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-c739e0cb598sm1080738a12.13.2026.03.06.01.45.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Mar 2026 01:45:21 -0800 (PST)
From: Jiakai Xu <jiakaipeanut@gmail.com>
To: ethan.w.s.graham@gmail.com
Cc: akpm@linux-foundation.org,
	andreyknvl@gmail.com,
	andy.shevchenko@gmail.com,
	andy@kernel.org,
	brauner@kernel.org,
	brendan.higgins@linux.dev,
	davem@davemloft.net,
	davidgow@google.com,
	dhowells@redhat.com,
	dvyukov@google.com,
	ebiggers@kernel.org,
	elver@google.com,
	glider@google.com,
	gregkh@linuxfoundation.org,
	herbert@gondor.apana.org.au,
	ignat@cloudflare.com,
	jack@suse.cz,
	jannh@google.com,
	johannes@sipsolutions.net,
	kasan-dev@googlegroups.com,
	kees@kernel.org,
	kunit-dev@googlegroups.com,
	linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	lukas@wunner.de,
	mcgrof@kernel.org,
	rmoar@google.com,
	shuah@kernel.org,
	sj@kernel.org,
	skhan@linuxfoundation.org,
	tarasmadan@google.com,
	wentaoz5@illinois.edu
Subject: Question about "stateless or low-state functions" in KFuzzTest doc
Date: Fri,  6 Mar 2026 17:44:58 +0800
Message-Id: <20260306094459.973-1-jiakaiPeanut@gmail.com>
X-Mailer: git-send-email 2.35.1.windows.2
In-Reply-To: <20260112192827.25989-4-ethan.w.s.graham@gmail.com>
References: <20260112192827.25989-4-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: jiakaipeanut@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=m5E8t8nR;       spf=pass
 (google.com: domain of jiakaipeanut@gmail.com designates 2607:f8b0:4864:20::430
 as permitted sender) smtp.mailfrom=jiakaipeanut@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
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
X-Rspamd-Queue-Id: E0D3621E295
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [0.29 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MID_CONTAINS_FROM(1.00)[];
	DMARC_POLICY_ALLOW(-0.50)[gmail.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,kernel.org,linux.dev,davemloft.net,google.com,redhat.com,linuxfoundation.org,gondor.apana.org.au,cloudflare.com,suse.cz,sipsolutions.net,googlegroups.com,vger.kernel.org,kvack.org,wunner.de,illinois.edu];
	FORGED_SENDER_MAILLIST(0.00)[];
	FREEMAIL_TO(0.00)[gmail.com];
	TAGGED_FROM(0.00)[bncBDJPLAN63YNBBM6EVLGQMGQETCHMZGQ];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[34];
	TO_DN_NONE(0.00)[];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_NEQ_ENVFROM(0.00)[jiakaipeanut@gmail.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	NEURAL_HAM(-0.00)[-1.000];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FREEMAIL_FROM(0.00)[gmail.com]
X-Rspamd-Action: no action

Hi Ethan and all,



I've been reading the KFuzzTest documentation patch (v4 3/6) with great 

interest. I have some questions about the scope and applicability of this 

framework that I'd like to discuss with the community.



The documentation states:

> It is intended for testing stateless or low-state functions that are 

> difficult to reach from the system call interface, such as routines 

> involved in file format parsing or complex data transformations.



I'm trying to better understand what qualifies as a "stateless or 

low-state function" in the kernel context. How do we define or identify 

whether a kernel function is stateless or low-state?



Also, I'm curious - what proportion of kernel functions would we 

estimate falls into this category?



Any insights would be greatly appreciated!



Thanks,

Jiakai

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260306094459.973-1-jiakaiPeanut%40gmail.com.
