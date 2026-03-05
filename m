Return-Path: <kasan-dev+bncBC4ZB2GTVUKBBUPVU3GQMGQEWZRMTPA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id oEqxDtS6qWnNDQEAu9opvQ
	(envelope-from <kasan-dev+bncBC4ZB2GTVUKBBUPVU3GQMGQEWZRMTPA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 18:18:12 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id CEC0121608A
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 18:18:11 +0100 (CET)
Received: by mail-oi1-x238.google.com with SMTP id 5614622812f47-45ca5b0a968sf82289590b6e.2
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 09:18:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772731090; cv=pass;
        d=google.com; s=arc-20240605;
        b=kdS2/pLwPP7hqL9nijAXFUuWm3x5p9Brocyh3cnGJRdAV9DHYwV1sNmvsGZPifknGJ
         lXGQCDqzZ24cGp2+9jM1xrQ9TS/kZf7DvM26EFe32yDQut64n+eZHa3ePHRy+/jUjkRp
         CSnxNdu0dozrvsW8sR1bSenEzZQtTdTeZTP1KzGSeQaNslRcVlsZVP/9C6Gvzv3KWl6I
         os7wtdSMxiSIw2kqJ3hvybWCcTqFTikSC5QmhYE7w5WVJwovCpFiho/DM8Bdc/P+elG7
         IKZT5PEU9oh1W+w6ZSJAAprva76HdCoQ7LTakdPdVhyEPb5TwumTbgdHwSD8niAj0NpB
         15Hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xMOHXTsadBkS7WNp9QpplFutVjd+qfMFjEbeCtyWxdI=;
        fh=B9cZcaOsDANkhPfyDfbRXl7FQ8FHzHiBOqpylBSj83g=;
        b=JPHIHQ9/diAIeR3qwlH+sgX7qfIJxNRxa1y7EOWwxbmfdUACF1oVLwQjOd9OVwFFDO
         AC/mx5yQ2VKNoJP6WLFSxeW9kyJrSLdNf1puFBNZvhXfCKa1HFRiIcY8UF/4wpu5k8Jv
         YDCGA0H1bKNwnXAdNdxfaj6XLZSYoq/K9QGLEatQzOTlq9TXdaO9MUM0oUmZZB6x7WRf
         aegFMu4vwbF+mXnTxvZDfHr3ZwEMVSF0t+DLX7QWSHdgO/N/Ec0fanZX4j4Lp02/BwTD
         vyOme/BOs/p4qa5Uyb6XOPfayzjUHTEoDJW9SGounp/2tm6vT8QzY9YWxozT+hjPE2ID
         3EZQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MV5bISf2;
       spf=pass (google.com: domain of song@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=song@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772731090; x=1773335890; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xMOHXTsadBkS7WNp9QpplFutVjd+qfMFjEbeCtyWxdI=;
        b=khVy5KtfyPwF0WCHr5xFGQB2g36wjKXX7Fk3qz6goQLw6wtwQwoHhhkYvxy+7l9noU
         +1fNYW+Ii86eUusb8bx9qelTrGiPL9JF6LHFPMoAiJUIJq0kMevF7DMXu5e3O40XtlOt
         pXfU+063rDLdCamXJ+JV3dn+cQxA7dNARAjkRd0DJ7pc6KfQMRgyte7oKxsUa9+pyu+e
         4fl5dhcNR7YCKARgHRo6FVVSsnN5GpqFn/YWKKWhRlkKPvuk7nwkFRxH+NvZTR30yLqO
         M6RaI1K5+I40IFLHmc+P6pBUHZQdxri9IxWuPLZPUoKahofQdlaf4omz6jyDhUVnHqSp
         jUrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772731090; x=1773335890;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xMOHXTsadBkS7WNp9QpplFutVjd+qfMFjEbeCtyWxdI=;
        b=sHyKFbAao9gxSsByswjB/PevVke85vv14gb6X522Q1pjikw8NHn+qu/sTHM3N2xkR0
         MRG+K1Iomn4Qh+VcUa9lkcoJ0wSTJCGc6BUwVATgJzvdA3MLhjZkzUjnTz/NWQsJiDbs
         tGbn4FGXg88rdvlzRphvs1yTUPHRVAMbQZHFuIppoQD3GKpMuS+5ijVAaAaIzc5ORoo0
         B3ELm5QNJIGKSoRi/TuQoqYggxTPjiipIgSO9guXxUMn5q0PyD1VR/norWGM6ewBwovA
         TOdLDztKTuozttfC5IHft5Ar+vdVe9ylKbVZNzI/oMW2a46l5RstAKiUT99xz9CBK/Hv
         qUWQ==
X-Forwarded-Encrypted: i=2; AJvYcCWcnsxma91VXb7L9j/dw2WkP7rF5wta9rrs7tbtXtB5YCJEVqa7eGNyXbtNy5W+ibubLKRU4w==@lfdr.de
X-Gm-Message-State: AOJu0YwenTHki7o2ZyJYWZunHhgOiriJ49o3BRLMd8unJOKxNRyUvUSs
	xyKZhjQPx2+2RqQ0OsCNZeZ5WSsHz9aT7kzn2n2hQicnpr6sfAzt//2R
X-Received: by 2002:a05:6808:2f19:b0:450:5e3a:6f1a with SMTP id 5614622812f47-4651abba7b9mr3529514b6e.20.1772731089680;
        Thu, 05 Mar 2026 09:18:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FfQrqAtDmteMh+b/qKDsU5qKlBrg6yyRAvq6Nv0NPGWA=="
Received: by 2002:a05:6871:81c5:10b0:3e8:4817:7a50 with SMTP id
 586e51a60fabf-416be66e7cfls484759fac.0.-pod-prod-05-us; Thu, 05 Mar 2026
 09:18:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVbFKdiA0UMIHvQI82sL/pVcI7mjp8Ln1lHw9JgRXH/CdfhSC217bHqYm2m1wlA02uuZmFEpJRTYgM=@googlegroups.com
X-Received: by 2002:a05:6830:3885:b0:743:8af2:1af7 with SMTP id 46e09a7af769-7d6d139f76amr3755166a34.23.1772731086803;
        Thu, 05 Mar 2026 09:18:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772731086; cv=none;
        d=google.com; s=arc-20240605;
        b=KYM7D1VagW2rbqfBYa57u3Bh1U0PUtjCLVlPpppi4+O4UdMD1c2Qmpejamy6o+pJ3L
         RPn+fheLeYJKQa5ZAHCk3RxJrBqkOoaFXPrJmdWCrgTNci+iFpLvd0kFGcu6clng3vug
         MPhS6+UTIwUPC8UhJBqJ8K5w/ydhkbQDQuTD3ciBgfuZAboGzmEnqhVkCrag25iSNGUr
         0N25abds7d9pfwIr36iLErMVaiKaTQBs+Ll9qpFRKFEJD5858Gj0C2pYgfJ5fPTYHbVF
         14B972mX6AUHEWcK9Z82hM0cLYMdUX1T3KdbFOV/ICRBQ3eI6Ose6HEdbdz/bLcf80Yq
         QvYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=LSzZiqAmnOieR7dWZbSZJYyJEhg+RhKcMy4uo1trHzc=;
        fh=3AEM00W4g1Rfa/R25OQJbe9W08AImYFwMb1TJtwCaGM=;
        b=PoHMMmc/RllemJ7T90XjfvrnHS8I9npo9QeABMSpZC+NXqBaj32/DsutrK46WN307P
         BVi7hvDXKQRQ2kScRBe517Z2EZA3v2mh6kmsXpmjz/J3QCQkcf02TMykFuNvRI+k3wbF
         c2jG9MDuExiDPs6s0KKB2uyCacEkopu4hBXOfgRUz4eDI+lBmLMXwKpDJFJNLJ/MQ7AJ
         RLf0eyrPgaTpJs5H+ov5Ng+8ukICWfnGH1RUDligGQQfkuJdcHaoYWhDgdmLUB8bscQv
         d6PAOy/G3G0rSLTLSRjy3xy2nBKO7Ywypiu4H9EBF0CE+9lQxfyBsJ+WuKwu9udz+HCV
         Cv/A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MV5bISf2;
       spf=pass (google.com: domain of song@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=song@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7d586619279si706828a34.5.2026.03.05.09.18.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Mar 2026 09:18:06 -0800 (PST)
Received-SPF: pass (google.com: domain of song@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 38E6B6001D
	for <kasan-dev@googlegroups.com>; Thu,  5 Mar 2026 17:18:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E1E09C4AF09
	for <kasan-dev@googlegroups.com>; Thu,  5 Mar 2026 17:18:05 +0000 (UTC)
Received: by mail-qv1-f43.google.com with SMTP id 6a1803df08f44-899f8c33c11so44061816d6.1
        for <kasan-dev@googlegroups.com>; Thu, 05 Mar 2026 09:18:05 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXRKC5jIdOU+C4AmeNMkdnusMduiHC/MgK+bnkHDizwpQlqAjylMFu+5lv6KyYCVaSoC7gIm0yzTN4=@googlegroups.com
X-Received: by 2002:a05:6214:dcb:b0:896:fbdd:ef14 with SMTP id
 6a1803df08f44-89a1998b305mr94807896d6.12.1772731085090; Thu, 05 Mar 2026
 09:18:05 -0800 (PST)
MIME-Version: 1.0
References: <20260305-wqstall_start-at-v2-0-b60863ee0899@debian.org> <20260305-wqstall_start-at-v2-4-b60863ee0899@debian.org>
In-Reply-To: <20260305-wqstall_start-at-v2-4-b60863ee0899@debian.org>
From: "'Song Liu' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Mar 2026 09:17:53 -0800
X-Gmail-Original-Message-ID: <CAPhsuW7oqEskpRwL+-Wsn=bCbVTA1QeDToPmUJZ=KXO9yYa7sQ@mail.gmail.com>
X-Gm-Features: AaiRm52qg3NONzYUkYLGmuBm7awa56UTcTS4OmT9VneHFpG76acFuYY5HML4yXs
Message-ID: <CAPhsuW7oqEskpRwL+-Wsn=bCbVTA1QeDToPmUJZ=KXO9yYa7sQ@mail.gmail.com>
Subject: Re: [PATCH v2 4/5] workqueue: Show all busy workers in stall diagnostics
To: Breno Leitao <leitao@debian.org>
Cc: Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-kernel@vger.kernel.org, 
	Omar Sandoval <osandov@osandov.com>, Danielle Costantino <dcostantino@meta.com>, kasan-dev@googlegroups.com, 
	Petr Mladek <pmladek@suse.com>, kernel-team@meta.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: song@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=MV5bISf2;       spf=pass
 (google.com: domain of song@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=song@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Song Liu <song@kernel.org>
Reply-To: Song Liu <song@kernel.org>
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
X-Rspamd-Queue-Id: CEC0121608A
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FREEMAIL_CC(0.00)[kernel.org,gmail.com,linux-foundation.org,vger.kernel.org,osandov.com,meta.com,googlegroups.com,suse.com];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_FROM(0.00)[bncBC4ZB2GTVUKBBUPVU3GQMGQEWZRMTPA];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	MISSING_XM_UA(0.00)[];
	HAS_REPLYTO(0.00)[song@kernel.org];
	NEURAL_HAM(-0.00)[-1.000];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_EQ_ENVFROM(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCPT_COUNT_SEVEN(0.00)[10];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:dkim,googlegroups.com:email,mail.gmail.com:mid,mail-oi1-x238.google.com:rdns,mail-oi1-x238.google.com:helo]
X-Rspamd-Action: no action

On Thu, Mar 5, 2026 at 8:16=E2=80=AFAM Breno Leitao <leitao@debian.org> wro=
te:
>
> show_cpu_pool_hog() only prints workers whose task is currently running
> on the CPU (task_is_running()).  This misses workers that are busy
> processing a work item but are sleeping or blocked =E2=80=94 for example,=
 a
> worker that clears PF_WQ_WORKER and enters wait_event_idle().  Such a
> worker still occupies a pool slot and prevents progress, yet produces
> an empty backtrace section in the watchdog output.
>
> This is happening on real arm64 systems, where
> toggle_allocation_gate() IPIs every single CPU in the machine (which
> lacks NMI), causing workqueue stalls that show empty backtraces because
> toggle_allocation_gate() is sleeping in wait_event_idle().
>
> Remove the task_is_running() filter so every in-flight worker in the
> pool's busy_hash is dumped.  The busy_hash is protected by pool->lock,
> which is already held.
>
> Signed-off-by: Breno Leitao <leitao@debian.org>

Acked-by: Song Liu <song@kernel.org>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
APhsuW7oqEskpRwL%2B-Wsn%3DbCbVTA1QeDToPmUJZ%3DKXO9yYa7sQ%40mail.gmail.com.
