Return-Path: <kasan-dev+bncBC7OD3FKWUERBSUIX7FQMGQEKKNYZJQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id IJrnCEzEb2lsMQAAu9opvQ
	(envelope-from <kasan-dev+bncBC7OD3FKWUERBSUIX7FQMGQEKKNYZJQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 19:07:08 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id A8EFD491A3
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 19:07:07 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-59b6d1d8986sf522550e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 10:07:07 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768932427; cv=pass;
        d=google.com; s=arc-20240605;
        b=Gvebyc3d28WJ1pPISYlRMLqM2v9x/qENaOxaJHfVsoI24gLSv1YMsLC4dq/Pr1ZbQm
         W2E88W5kswwvOcOMvc6Y7v4cdj/6T0G4ORFwPjLEIFWzd/H9BFHJSG1xG/KnJ+Y5cm2E
         SyTpwY/d6ygyg4l4wiDabu9Gp0CzQnE4h2dHZRF+QiKyQTCgZoWhHxooV1bp+pvH6nS2
         S3Qf6BWE85KzQ+hQnFdrpgN8aG+pfDp5+c8OJFOc/Q427MQpyWlDMmf5CnvH1bVDnGNn
         WCZbLK0kG4mqRP3ucwnnUwtVCs0aJE8ehupv6WrvBGBqrHBqviru+13qowyVEp7w6zXE
         yVcg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MCj71k9NLsif7jdAGDVCRLfqPoGJrTawf1ueWK7RzCE=;
        fh=tYD4JF5PNsK30640PNjLgYKpVn6fYa2ayGes4jdZUlk=;
        b=coyZHsfrGUJ7bwngMrTLbpsMUOX+nnbbF/9nh0RIvzxLXK14EMM3OAHVJWQ3kyqNlg
         eRMQOiRf9SXajenTzWpaAzThjCzuSSAFI+3W0G5NwypNe7TUJuWwQjFyx8Gi2S0AZlmV
         SENklZaUv2GvV+ELr/7zv41ZiTTBp/CPCu081P2UPVxvnkXHUnqHxgQmwVtZn6rfNGcV
         cFaKfCnFItQuWytIfPxuJdjscZG1ismI3ykRl4xgFo3RYbMKXJc4MUSjpEaPPTODe75d
         n8RJmNJtEGYxOsOZ8cdQYrs3qutQ8ksS3n9AbpJbvrV/pXPKRkssIPFV7oAR+roXvuFi
         w9Uw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hlV9zY+x;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::52b as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768932427; x=1769537227; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MCj71k9NLsif7jdAGDVCRLfqPoGJrTawf1ueWK7RzCE=;
        b=losP2TCCueyv2b6yksHTe9NIe3NPCJL99n5AWkZgounReUFm0C3PmZ/G/QIKYexwJI
         OzRBK3O010EQhwfCVhD9pbHvYcQm3tBZdhGKFOkVgnjU77NqnYO973Z9z8iQArITJuYH
         asWCHNIvEfTBlO8zkUz3Q7/Mo+xMZz5kGsUUIC+wjcmKjnyty+9c/sjNSYnQfNytn68K
         IUVD2aLLdD6ccczqySmBNSWSu8ThLKlc1VQQiEHXygepAzwIn9ggBHlxF7JY3q5LbrRd
         bYft2TQQQESg1mGc0ljVWRkCrHZa9Gt37GxkWGgczFYm5ZY6A1nhsbAYkRQJTMsOl8N5
         j82Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768932427; x=1769537227;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=MCj71k9NLsif7jdAGDVCRLfqPoGJrTawf1ueWK7RzCE=;
        b=qJmqHz4Ju3tDPetnz2cCoGx9FDcPa6GajNMg3+3MwuOsj91YZ0jCsG7wmfYRzxdR3j
         zjMJAIdazJNs2kGeIcW0G8FW6TGP+TwEcO2NjXwJSnSUjW6U95paPav2lP+4+9Zv3AFl
         s2RCjxVHJoU7tFKC1R8ib3kJey/2kOrW0Z1qYYY52sSpkN0U7vP67LIZiEMu7XG9zENt
         DjtteNsmLuXp9GL7WKxhp3scKFHRL+lv+WFwAtet0px7KugfQYD0opp2y+E/B8p/YR+M
         IWygNsp1hMiYwkPHYaPir2tm7bkOAqQ/Ouh19AobN+X+fxFIrD3oSctkr9oO4GmZe4su
         actg==
X-Forwarded-Encrypted: i=3; AJvYcCXsNYFYjgXati8jsk74TBXXBx3PYhJbaK5dvmKB16vVsud/s5JJNuPu334RGWv+MD1Y6y8iTw==@lfdr.de
X-Gm-Message-State: AOJu0YwQd4zzE/HkkgdTRGqSeEla7TgyzwsyZQeyGtZ9kLQCZLEW1Eo0
	t5JeLD9Heh3YIRceEzWlFMNDh8UNqgVCfpSCxFqqf9yAnc8LM/4FAynC
X-Received: by 2002:a05:6512:251f:b0:59d:c709:a863 with SMTP id 2adb3069b0e04-59dc709ab1emr775397e87.0.1768932426614;
        Tue, 20 Jan 2026 10:07:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HkVF5xVpuaDEuJ/x0tXtz3YEmWVbLWj0tghmQQ+/OXfw=="
Received: by 2002:a05:6512:2248:b0:59b:a3bb:9e0f with SMTP id
 2adb3069b0e04-59ba718b835ls2021063e87.2.-pod-prod-01-eu; Tue, 20 Jan 2026
 10:07:03 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWcpWP94AkxB/hJrUA9BwBpRzlhV4hIJHnrOLr6Cqg/EaZIAr5Of7qsNPO5LMo+Ec1scfUug0BccFQ=@googlegroups.com
X-Received: by 2002:a05:6512:159f:b0:59c:b87a:d603 with SMTP id 2adb3069b0e04-59cb87ad6c0mr3474400e87.6.1768932422793;
        Tue, 20 Jan 2026 10:07:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768932422; cv=pass;
        d=google.com; s=arc-20240605;
        b=VECtx+ZLR2QVQbWntnITLsviBWZaUV5WuWA3/Gos3ZIcN194HiLHEROixJWU0NTJiP
         eSFucxxoRyqSbA6F26z7dWZa9vvh8DaUCKOAEo0yliFY5yqvCPVtK4vx4ETKPfZxqp4S
         Ek6p9Mgwx+fODuyxGhK0tRmsST4Z47/cMmaFGIr9vEv73NEwoBD5sVvdY70CYsDF++o1
         HVM23oJsGOqh7ZYkc84gtOIREMJOd5kMAsQAmo66X0e3wUwbzhQTqiZpmz9r/yMilt2V
         /yhKw5BHnSD+JPlSFO7ifUKQ69NeSdQ0+ZTY1n6cmmyPfpHsPSac7l1jG0xac4sRdqfx
         Zfsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=0m4EgKcvHAigyFoIen3o4lxoSu/pBeXLeIue1VEAhmI=;
        fh=b4DQubvjOeUnwk4ycZYcuAl3cOXGENHU6O/JkTsGV9A=;
        b=EyEzdrxvYn+K8rR6agiQmQvGa0ZcU3+0qS+Cft+oBIdNJLpOZHSklExpmqQ5wBL558
         dWLBYRyb47CLuo5V0oelKFcHYobFzV6h1Pqld+TMDpBsktFsxWNDB5IQWUWYp7DI9nvK
         7cysD0qIcsZ40lVS+btgtlsdksDrDhcOD01j7jymHvX0Tyb5VYmJKdX3evaUT49X6+jH
         ZfWPz7QpAUlsxPc+s35l140vt1ZK/XiowbX5//vHNSAgxHiPAuCA4EjIqBtMIqe2qqa7
         uWuUvA/qvv6X7G5DAFGLBc/4WGYmAPrbAW3D+e1Gb5EUrKsekdqtWWbpH+Va49200Jbu
         xGqg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hlV9zY+x;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::52b as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52b.google.com (mail-ed1-x52b.google.com. [2a00:1450:4864:20::52b])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59baf38ee84si228769e87.3.2026.01.20.10.07.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jan 2026 10:07:02 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::52b as permitted sender) client-ip=2a00:1450:4864:20::52b;
Received: by mail-ed1-x52b.google.com with SMTP id 4fb4d7f45d1cf-657fec06242so340a12.1
        for <kasan-dev@googlegroups.com>; Tue, 20 Jan 2026 10:07:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768932422; cv=none;
        d=google.com; s=arc-20240605;
        b=FqL2wvgzwecfX/6wBx69ES/jyVHNm/9gxEP9P+LcM6CHmbrZgQd0EKF60miwBbTUUx
         aE4gNhWJ4yUpGYFPTwUZWGatFmmbVSld+7My6dnCYW/+UzUYxsfHu6thj1T1bOLSTj/C
         +1TqIrczrLUqb3O96WNDzKUqMGjtPnMaDyPU30uulvbfei8DpducA4ac7sNQa9gpX/Rx
         IqcwXzFQXrxrYZci3UzKrSClfKtzBYCaLI07sG2rSctj+BcbyOS4o8TVB5ueIR7oU+6v
         T+V+J8PxSbkqRohqqvvu1+CPpzwsgPQASF+U1TD0W+qwdA3C/RqMZxayh01Lju+gWKAt
         VssQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=0m4EgKcvHAigyFoIen3o4lxoSu/pBeXLeIue1VEAhmI=;
        fh=b4DQubvjOeUnwk4ycZYcuAl3cOXGENHU6O/JkTsGV9A=;
        b=UAwAOEeIZ+oSS1XHX1f0Fk3z0Xsdb4mb7etAnzWcrafe3PjDnilDam9bOxVeGlfFRt
         mrWV2uZ5v7p8/JAEr7HxvPZ0RFZvOUGuDw6XHv39VxJdLfjNtPCkGzjCQsgsMSViF5Tq
         QeXWLtkK2ti/oOXkBNFUnmPy9tLXSwum3Qtyvmi1rptSCgjhOhdK8RiBJvJI6d3mnM2A
         M1Gs2vG9+l27Ueec4q2GXlWSc++nOPWu32Kic/gtr+Fh3gWAlvANrqg4s7jg1+fCZtqf
         kz052ERK3rmJOgNu8qKn2WFSquo6y10CvU1pGmwkmztEdFXp+i0DK+dbMZuCZQABa8yy
         Jdlg==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCXvLCqL1NaDL7nWZEVEmL87byQcWCAj6TGs6bsFskA3Ns5HV2M0uCY9OrcAUwQZHBxFls1XCsMY8lc=@googlegroups.com
X-Gm-Gg: AZuq6aIhFZGmODRqUAxB2AXfAGINi6SYwLJ1WQH5/3p7TYVsdvpdIDddNIZJgYq1MY4
	DukwohsL4t4qQuCkV/80IeU2gjIsh7f7ORXKfeOo9iBeNH5PTTP/W6K8vXYUR+Qk20wneXOG047
	PT7bgXUDsfwG2EKSOA6FgwhslppukDqOaTUobfQ1ueactPm6YXft5BQD1FH/Wn4QEWtCTKAxSu5
	BG5V2+ftp/OGr2LwY5xGCcQpnOTINwoXLPE5Q3GtFpGcZzbE1PJZ0dv59Y/pOiXUQIar8Xn/Nsc
	PvtupY1mpK9CdUuOv7S6tLw=
X-Received: by 2002:a05:6402:1659:b0:658:e7a:6fa7 with SMTP id
 4fb4d7f45d1cf-6581398f92amr1073a12.4.1768932421563; Tue, 20 Jan 2026 10:07:01
 -0800 (PST)
MIME-Version: 1.0
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz> <20260116-sheaves-for-all-v3-10-5595cb000772@suse.cz>
In-Reply-To: <20260116-sheaves-for-all-v3-10-5595cb000772@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 20 Jan 2026 18:06:46 +0000
X-Gm-Features: AZwV_QhAI_v8nb72cx00QIZiPM3CMYUd_28UNx83-h0Ivydma0yfYiVC7xf4sY0
Message-ID: <CAJuCfpEEUs98yCiNA=QOPY6Qk7=QhSBF+gqPn5a+B+bYbQwvsQ@mail.gmail.com>
Subject: Re: [PATCH v3 10/21] slab: remove cpu (partial) slabs usage from
 allocation paths
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>, 
	Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=hlV9zY+x;       arc=pass
 (i=1);       spf=pass (google.com: domain of surenb@google.com designates
 2a00:1450:4864:20::52b as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC7OD3FKWUERBSUIX7FQMGQEKKNYZJQ];
	RCVD_COUNT_THREE(0.00)[4];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[surenb@google.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,googlegroups.com:email,googlegroups.com:dkim,suse.cz:email,mail-lf1-x138.google.com:rdns,mail-lf1-x138.google.com:helo]
X-Rspamd-Queue-Id: A8EFD491A3
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Fri, Jan 16, 2026 at 2:40=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> We now rely on sheaves as the percpu caching layer and can refill them
> directly from partial or newly allocated slabs. Start removing the cpu
> (partial) slabs code, first from allocation paths.
>
> This means that any allocation not satisfied from percpu sheaves will
> end up in ___slab_alloc(), where we remove the usage of cpu (partial)
> slabs, so it will only perform get_partial() or new_slab(). In the
> latter case we reuse alloc_from_new_slab() (when we don't use
> the debug/tiny alloc_single_from_new_slab() variant).
>
> In get_partial_node() we used to return a slab for freezing as the cpu
> slab and to refill the partial slab. Now we only want to return a single
> object and leave the slab on the list (unless it became full). We can't
> simply reuse alloc_single_from_partial() as that assumes freeing uses
> free_to_partial_list(). Instead we need to use __slab_update_freelist()
> to work properly against a racing __slab_free().
>
> The rest of the changes is removing functions that no longer have any
> callers.
>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

A couple of nits, but otherwise seems fine to me.

Reviewed-by: Suren Baghdasaryan <surenb@google.com>

> ---
>  mm/slub.c | 612 ++++++++------------------------------------------------=
------
>  1 file changed, 79 insertions(+), 533 deletions(-)
>
> diff --git a/mm/slub.c b/mm/slub.c
> index dce80463f92c..698c0d940f06 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -245,7 +245,6 @@ static DEFINE_STATIC_KEY_FALSE(strict_numa);
>  struct partial_context {
>         gfp_t flags;
>         unsigned int orig_size;
> -       void *object;
>         unsigned int min_objects;
>         unsigned int max_objects;
>         struct list_head slabs;
> @@ -611,36 +610,6 @@ static inline void *get_freepointer(struct kmem_cach=
e *s, void *object)
>         return freelist_ptr_decode(s, p, ptr_addr);
>  }
>
> -static void prefetch_freepointer(const struct kmem_cache *s, void *objec=
t)
> -{
> -       prefetchw(object + s->offset);
> -}
> -
> -/*
> - * When running under KMSAN, get_freepointer_safe() may return an uninit=
ialized
> - * pointer value in the case the current thread loses the race for the n=
ext
> - * memory chunk in the freelist. In that case this_cpu_cmpxchg_double() =
in
> - * slab_alloc_node() will fail, so the uninitialized value won't be used=
, but
> - * KMSAN will still check all arguments of cmpxchg because of imperfect
> - * handling of inline assembly.
> - * To work around this problem, we apply __no_kmsan_checks to ensure tha=
t
> - * get_freepointer_safe() returns initialized memory.
> - */
> -__no_kmsan_checks
> -static inline void *get_freepointer_safe(struct kmem_cache *s, void *obj=
ect)
> -{
> -       unsigned long freepointer_addr;
> -       freeptr_t p;
> -
> -       if (!debug_pagealloc_enabled_static())
> -               return get_freepointer(s, object);
> -
> -       object =3D kasan_reset_tag(object);
> -       freepointer_addr =3D (unsigned long)object + s->offset;
> -       copy_from_kernel_nofault(&p, (freeptr_t *)freepointer_addr, sizeo=
f(p));
> -       return freelist_ptr_decode(s, p, freepointer_addr);
> -}
> -
>  static inline void set_freepointer(struct kmem_cache *s, void *object, v=
oid *fp)
>  {
>         unsigned long freeptr_addr =3D (unsigned long)object + s->offset;
> @@ -720,23 +689,11 @@ static void slub_set_cpu_partial(struct kmem_cache =
*s, unsigned int nr_objects)
>         nr_slabs =3D DIV_ROUND_UP(nr_objects * 2, oo_objects(s->oo));
>         s->cpu_partial_slabs =3D nr_slabs;
>  }
> -
> -static inline unsigned int slub_get_cpu_partial(struct kmem_cache *s)
> -{
> -       return s->cpu_partial_slabs;
> -}
> -#else
> -#ifdef SLAB_SUPPORTS_SYSFS
> +#elif defined(SLAB_SUPPORTS_SYSFS)
>  static inline void
>  slub_set_cpu_partial(struct kmem_cache *s, unsigned int nr_objects)
>  {
>  }
> -#endif
> -
> -static inline unsigned int slub_get_cpu_partial(struct kmem_cache *s)
> -{
> -       return 0;
> -}
>  #endif /* CONFIG_SLUB_CPU_PARTIAL */
>
>  /*
> @@ -1077,7 +1034,7 @@ static void set_track_update(struct kmem_cache *s, =
void *object,
>         p->handle =3D handle;
>  #endif
>         p->addr =3D addr;
> -       p->cpu =3D smp_processor_id();
> +       p->cpu =3D raw_smp_processor_id();
>         p->pid =3D current->pid;
>         p->when =3D jiffies;
>  }
> @@ -3583,15 +3540,15 @@ static bool get_partial_node_bulk(struct kmem_cac=
he *s,
>  }
>
>  /*
> - * Try to allocate a partial slab from a specific node.
> + * Try to allocate object from a partial slab on a specific node.
>   */
> -static struct slab *get_partial_node(struct kmem_cache *s,
> -                                    struct kmem_cache_node *n,
> -                                    struct partial_context *pc)
> +static void *get_partial_node(struct kmem_cache *s,
> +                             struct kmem_cache_node *n,
> +                             struct partial_context *pc)

Naming for get_partial()/get_partial_node()/get_any_partial() made
sense when they returned a slab. Now that they return object(s) the
naming is a bit confusing. I think renaming to
get_from_partial()/get_from_partial_node()/get_from_any_partial()
would be more appropriate.

>  {
> -       struct slab *slab, *slab2, *partial =3D NULL;
> +       struct slab *slab, *slab2;
>         unsigned long flags;
> -       unsigned int partial_slabs =3D 0;
> +       void *object =3D NULL;
>
>         /*
>          * Racy check. If we mistakenly see no partial slabs then we
> @@ -3607,54 +3564,55 @@ static struct slab *get_partial_node(struct kmem_=
cache *s,
>         else if (!spin_trylock_irqsave(&n->list_lock, flags))
>                 return NULL;
>         list_for_each_entry_safe(slab, slab2, &n->partial, slab_list) {
> +
> +               struct freelist_counters old, new;
> +
>                 if (!pfmemalloc_match(slab, pc->flags))
>                         continue;
>
>                 if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) =
{
> -                       void *object =3D alloc_single_from_partial(s, n, =
slab,
> +                       object =3D alloc_single_from_partial(s, n, slab,
>                                                         pc->orig_size);
> -                       if (object) {
> -                               partial =3D slab;
> -                               pc->object =3D object;
> +                       if (object)
>                                 break;
> -                       }
>                         continue;
>                 }
>
> -               remove_partial(n, slab);
> +               /*
> +                * get a single object from the slab. This might race aga=
inst
> +                * __slab_free(), which however has to take the list_lock=
 if
> +                * it's about to make the slab fully free.
> +                */
> +               do {
> +                       old.freelist =3D slab->freelist;
> +                       old.counters =3D slab->counters;
>
> -               if (!partial) {
> -                       partial =3D slab;
> -                       stat(s, ALLOC_FROM_PARTIAL);
> +                       new.freelist =3D get_freepointer(s, old.freelist)=
;
> +                       new.counters =3D old.counters;
> +                       new.inuse++;
>
> -                       if ((slub_get_cpu_partial(s) =3D=3D 0)) {
> -                               break;
> -                       }
> -               } else {
> -                       put_cpu_partial(s, slab, 0);
> -                       stat(s, CPU_PARTIAL_NODE);
> +               } while (!__slab_update_freelist(s, slab, &old, &new, "ge=
t_partial_node"));
>
> -                       if (++partial_slabs > slub_get_cpu_partial(s) / 2=
) {
> -                               break;
> -                       }
> -               }
> +               object =3D old.freelist;
> +               if (!new.freelist)
> +                       remove_partial(n, slab);
> +
> +               break;
>         }
>         spin_unlock_irqrestore(&n->list_lock, flags);
> -       return partial;
> +       return object;
>  }
>
>  /*
> - * Get a slab from somewhere. Search in increasing NUMA distances.
> + * Get an object from somewhere. Search in increasing NUMA distances.
>   */
> -static struct slab *get_any_partial(struct kmem_cache *s,
> -                                   struct partial_context *pc)
> +static void *get_any_partial(struct kmem_cache *s, struct partial_contex=
t *pc)
>  {
>  #ifdef CONFIG_NUMA
>         struct zonelist *zonelist;
>         struct zoneref *z;
>         struct zone *zone;
>         enum zone_type highest_zoneidx =3D gfp_zone(pc->flags);
> -       struct slab *slab;
>         unsigned int cpuset_mems_cookie;
>
>         /*
> @@ -3689,8 +3647,10 @@ static struct slab *get_any_partial(struct kmem_ca=
che *s,
>
>                         if (n && cpuset_zone_allowed(zone, pc->flags) &&
>                                         n->nr_partial > s->min_partial) {
> -                               slab =3D get_partial_node(s, n, pc);
> -                               if (slab) {
> +
> +                               void *object =3D get_partial_node(s, n, p=
c);
> +
> +                               if (object) {
>                                         /*
>                                          * Don't check read_mems_allowed_=
retry()
>                                          * here - if mems_allowed was upd=
ated in
> @@ -3698,7 +3658,7 @@ static struct slab *get_any_partial(struct kmem_cac=
he *s,
>                                          * between allocation and the cpu=
set
>                                          * update
>                                          */
> -                                       return slab;
> +                                       return object;
>                                 }
>                         }
>                 }
> @@ -3708,20 +3668,20 @@ static struct slab *get_any_partial(struct kmem_c=
ache *s,
>  }
>
>  /*
> - * Get a partial slab, lock it and return it.
> + * Get an object from a partial slab
>   */
> -static struct slab *get_partial(struct kmem_cache *s, int node,
> -                               struct partial_context *pc)
> +static void *get_partial(struct kmem_cache *s, int node,
> +                        struct partial_context *pc)
>  {
> -       struct slab *slab;
>         int searchnode =3D node;
> +       void *object;
>
>         if (node =3D=3D NUMA_NO_NODE)
>                 searchnode =3D numa_mem_id();
>
> -       slab =3D get_partial_node(s, get_node(s, searchnode), pc);
> -       if (slab || (node !=3D NUMA_NO_NODE && (pc->flags & __GFP_THISNOD=
E)))
> -               return slab;
> +       object =3D get_partial_node(s, get_node(s, searchnode), pc);
> +       if (object || (node !=3D NUMA_NO_NODE && (pc->flags & __GFP_THISN=
ODE)))
> +               return object;
>
>         return get_any_partial(s, pc);
>  }
> @@ -4281,19 +4241,6 @@ static int slub_cpu_dead(unsigned int cpu)
>         return 0;
>  }
>
> -/*
> - * Check if the objects in a per cpu structure fit numa
> - * locality expectations.
> - */
> -static inline int node_match(struct slab *slab, int node)
> -{
> -#ifdef CONFIG_NUMA
> -       if (node !=3D NUMA_NO_NODE && slab_nid(slab) !=3D node)
> -               return 0;
> -#endif
> -       return 1;
> -}
> -
>  #ifdef CONFIG_SLUB_DEBUG
>  static int count_free(struct slab *slab)
>  {
> @@ -4478,36 +4425,6 @@ __update_cpu_freelist_fast(struct kmem_cache *s,
>                                              &old.freelist_tid, new.freel=
ist_tid);
>  }
>
> -/*
> - * Check the slab->freelist and either transfer the freelist to the
> - * per cpu freelist or deactivate the slab.
> - *
> - * The slab is still frozen if the return value is not NULL.
> - *
> - * If this function returns NULL then the slab has been unfrozen.
> - */
> -static inline void *get_freelist(struct kmem_cache *s, struct slab *slab=
)
> -{
> -       struct freelist_counters old, new;
> -
> -       lockdep_assert_held(this_cpu_ptr(&s->cpu_slab->lock));
> -
> -       do {
> -               old.freelist =3D slab->freelist;
> -               old.counters =3D slab->counters;
> -
> -               new.freelist =3D NULL;
> -               new.counters =3D old.counters;
> -
> -               new.inuse =3D old.objects;
> -               new.frozen =3D old.freelist !=3D NULL;
> -
> -
> -       } while (!__slab_update_freelist(s, slab, &old, &new, "get_freeli=
st"));
> -
> -       return old.freelist;
> -}
> -
>  /*
>   * Get the slab's freelist and do not freeze it.
>   *
> @@ -4535,29 +4452,6 @@ static inline void *get_freelist_nofreeze(struct k=
mem_cache *s, struct slab *sla
>         return old.freelist;
>  }
>
> -/*
> - * Freeze the partial slab and return the pointer to the freelist.
> - */
> -static inline void *freeze_slab(struct kmem_cache *s, struct slab *slab)
> -{
> -       struct freelist_counters old, new;
> -
> -       do {
> -               old.freelist =3D slab->freelist;
> -               old.counters =3D slab->counters;
> -
> -               new.freelist =3D NULL;
> -               new.counters =3D old.counters;
> -               VM_BUG_ON(new.frozen);
> -
> -               new.inuse =3D old.objects;
> -               new.frozen =3D 1;
> -
> -       } while (!slab_update_freelist(s, slab, &old, &new, "freeze_slab"=
));
> -
> -       return old.freelist;
> -}
> -
>  /*
>   * If the object has been wiped upon free, make sure it's fully initiali=
zed by
>   * zeroing out freelist pointer.
> @@ -4618,170 +4512,23 @@ static unsigned int alloc_from_new_slab(struct k=
mem_cache *s, struct slab *slab,
>  }
>
>  /*
> - * Slow path. The lockless freelist is empty or we need to perform
> - * debugging duties.
> - *
> - * Processing is still very fast if new objects have been freed to the
> - * regular freelist. In that case we simply take over the regular freeli=
st
> - * as the lockless freelist and zap the regular freelist.
> - *
> - * If that is not working then we fall back to the partial lists. We tak=
e the
> - * first element of the freelist as the object to allocate now and move =
the
> - * rest of the freelist to the lockless freelist.
> - *
> - * And if we were unable to get a new slab from the partial slab lists t=
hen
> - * we need to allocate a new slab. This is the slowest path since it inv=
olves
> - * a call to the page allocator and the setup of a new slab.
> + * Slow path. We failed to allocate via percpu sheaves or they are not a=
vailable
> + * due to bootstrap or debugging enabled or SLUB_TINY.
>   *
> - * Version of __slab_alloc to use when we know that preemption is
> - * already disabled (which is the case for bulk allocation).
> + * We try to allocate from partial slab lists and fall back to allocatin=
g a new
> + * slab.
>   */
>  static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int nod=
e,
> -                         unsigned long addr, struct kmem_cache_cpu *c, u=
nsigned int orig_size)
> +                          unsigned long addr, unsigned int orig_size)
>  {
>         bool allow_spin =3D gfpflags_allow_spinning(gfpflags);
>         void *freelist;
>         struct slab *slab;
> -       unsigned long flags;
>         struct partial_context pc;
>         bool try_thisnode =3D true;
>
>         stat(s, ALLOC_SLOWPATH);
>
> -reread_slab:
> -
> -       slab =3D READ_ONCE(c->slab);
> -       if (!slab) {
> -               /*
> -                * if the node is not online or has no normal memory, jus=
t
> -                * ignore the node constraint
> -                */
> -               if (unlikely(node !=3D NUMA_NO_NODE &&
> -                            !node_isset(node, slab_nodes)))
> -                       node =3D NUMA_NO_NODE;
> -               goto new_slab;
> -       }
> -
> -       if (unlikely(!node_match(slab, node))) {
> -               /*
> -                * same as above but node_match() being false already
> -                * implies node !=3D NUMA_NO_NODE.
> -                *
> -                * We don't strictly honor pfmemalloc and NUMA preference=
s
> -                * when !allow_spin because:
> -                *
> -                * 1. Most kmalloc() users allocate objects on the local =
node,
> -                *    so kmalloc_nolock() tries not to interfere with the=
m by
> -                *    deactivating the cpu slab.
> -                *
> -                * 2. Deactivating due to NUMA or pfmemalloc mismatch may=
 cause
> -                *    unnecessary slab allocations even when n->partial l=
ist
> -                *    is not empty.
> -                */
> -               if (!node_isset(node, slab_nodes) ||
> -                   !allow_spin) {
> -                       node =3D NUMA_NO_NODE;
> -               } else {
> -                       stat(s, ALLOC_NODE_MISMATCH);
> -                       goto deactivate_slab;
> -               }
> -       }
> -
> -       /*
> -        * By rights, we should be searching for a slab page that was
> -        * PFMEMALLOC but right now, we are losing the pfmemalloc
> -        * information when the page leaves the per-cpu allocator
> -        */
> -       if (unlikely(!pfmemalloc_match(slab, gfpflags) && allow_spin))
> -               goto deactivate_slab;
> -
> -       /* must check again c->slab in case we got preempted and it chang=
ed */
> -       local_lock_cpu_slab(s, flags);
> -
> -       if (unlikely(slab !=3D c->slab)) {
> -               local_unlock_cpu_slab(s, flags);
> -               goto reread_slab;
> -       }
> -       freelist =3D c->freelist;
> -       if (freelist)
> -               goto load_freelist;
> -
> -       freelist =3D get_freelist(s, slab);
> -
> -       if (!freelist) {
> -               c->slab =3D NULL;
> -               c->tid =3D next_tid(c->tid);
> -               local_unlock_cpu_slab(s, flags);
> -               stat(s, DEACTIVATE_BYPASS);
> -               goto new_slab;
> -       }
> -
> -       stat(s, ALLOC_REFILL);
> -
> -load_freelist:
> -
> -       lockdep_assert_held(this_cpu_ptr(&s->cpu_slab->lock));
> -
> -       /*
> -        * freelist is pointing to the list of objects to be used.
> -        * slab is pointing to the slab from which the objects are obtain=
ed.
> -        * That slab must be frozen for per cpu allocations to work.
> -        */
> -       VM_BUG_ON(!c->slab->frozen);
> -       c->freelist =3D get_freepointer(s, freelist);
> -       c->tid =3D next_tid(c->tid);
> -       local_unlock_cpu_slab(s, flags);
> -       return freelist;
> -
> -deactivate_slab:
> -
> -       local_lock_cpu_slab(s, flags);
> -       if (slab !=3D c->slab) {
> -               local_unlock_cpu_slab(s, flags);
> -               goto reread_slab;
> -       }
> -       freelist =3D c->freelist;
> -       c->slab =3D NULL;
> -       c->freelist =3D NULL;
> -       c->tid =3D next_tid(c->tid);
> -       local_unlock_cpu_slab(s, flags);
> -       deactivate_slab(s, slab, freelist);
> -
> -new_slab:
> -
> -#ifdef CONFIG_SLUB_CPU_PARTIAL
> -       while (slub_percpu_partial(c)) {
> -               local_lock_cpu_slab(s, flags);
> -               if (unlikely(c->slab)) {
> -                       local_unlock_cpu_slab(s, flags);
> -                       goto reread_slab;
> -               }
> -               if (unlikely(!slub_percpu_partial(c))) {
> -                       local_unlock_cpu_slab(s, flags);
> -                       /* we were preempted and partial list got empty *=
/
> -                       goto new_objects;
> -               }
> -
> -               slab =3D slub_percpu_partial(c);
> -               slub_set_percpu_partial(c, slab);
> -
> -               if (likely(node_match(slab, node) &&
> -                          pfmemalloc_match(slab, gfpflags)) ||
> -                   !allow_spin) {
> -                       c->slab =3D slab;
> -                       freelist =3D get_freelist(s, slab);
> -                       VM_BUG_ON(!freelist);
> -                       stat(s, CPU_PARTIAL_ALLOC);
> -                       goto load_freelist;
> -               }
> -
> -               local_unlock_cpu_slab(s, flags);
> -
> -               slab->next =3D NULL;
> -               __put_partials(s, slab);
> -       }
> -#endif
> -
>  new_objects:
>
>         pc.flags =3D gfpflags;
> @@ -4806,33 +4553,11 @@ static void *___slab_alloc(struct kmem_cache *s, =
gfp_t gfpflags, int node,
>         }
>
>         pc.orig_size =3D orig_size;
> -       slab =3D get_partial(s, node, &pc);
> -       if (slab) {
> -               if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) =
{
> -                       freelist =3D pc.object;
> -                       /*
> -                        * For debug caches here we had to go through
> -                        * alloc_single_from_partial() so just store the
> -                        * tracking info and return the object.
> -                        *
> -                        * Due to disabled preemption we need to disallow
> -                        * blocking. The flags are further adjusted by
> -                        * gfp_nested_mask() in stack_depot itself.
> -                        */
> -                       if (s->flags & SLAB_STORE_USER)
> -                               set_track(s, freelist, TRACK_ALLOC, addr,
> -                                         gfpflags & ~(__GFP_DIRECT_RECLA=
IM));
> -
> -                       return freelist;
> -               }
> -
> -               freelist =3D freeze_slab(s, slab);
> -               goto retry_load_slab;
> -       }
> +       freelist =3D get_partial(s, node, &pc);

I think all this cleanup results in this `freelist` variable being
used to always store a single object. Maybe rename it into `object`?

> +       if (freelist)
> +               goto success;
>
> -       slub_put_cpu_ptr(s->cpu_slab);
>         slab =3D new_slab(s, pc.flags, node);
> -       c =3D slub_get_cpu_ptr(s->cpu_slab);
>
>         if (unlikely(!slab)) {
>                 if (node !=3D NUMA_NO_NODE && !(gfpflags & __GFP_THISNODE=
)
> @@ -4849,68 +4574,29 @@ static void *___slab_alloc(struct kmem_cache *s, =
gfp_t gfpflags, int node,
>         if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
>                 freelist =3D alloc_single_from_new_slab(s, slab, orig_siz=
e, gfpflags);
>
> -               if (unlikely(!freelist)) {
> -                       /* This could cause an endless loop. Fail instead=
. */
> -                       if (!allow_spin)
> -                               return NULL;
> -                       goto new_objects;
> -               }
> -
> -               if (s->flags & SLAB_STORE_USER)
> -                       set_track(s, freelist, TRACK_ALLOC, addr,
> -                                 gfpflags & ~(__GFP_DIRECT_RECLAIM));
> -
> -               return freelist;
> -       }
> -
> -       /*
> -        * No other reference to the slab yet so we can
> -        * muck around with it freely without cmpxchg
> -        */
> -       freelist =3D slab->freelist;
> -       slab->freelist =3D NULL;
> -       slab->inuse =3D slab->objects;
> -       slab->frozen =3D 1;
> -
> -       inc_slabs_node(s, slab_nid(slab), slab->objects);
> +               if (likely(freelist))
> +                       goto success;
> +       } else {
> +               alloc_from_new_slab(s, slab, &freelist, 1, allow_spin);
>
> -       if (unlikely(!pfmemalloc_match(slab, gfpflags) && allow_spin)) {
> -               /*
> -                * For !pfmemalloc_match() case we don't load freelist so=
 that
> -                * we don't make further mismatched allocations easier.
> -                */
> -               deactivate_slab(s, slab, get_freepointer(s, freelist));
> -               return freelist;
> +               /* we don't need to check SLAB_STORE_USER here */
> +               if (likely(freelist))
> +                       return freelist;
>         }
>
> -retry_load_slab:
> -
> -       local_lock_cpu_slab(s, flags);
> -       if (unlikely(c->slab)) {
> -               void *flush_freelist =3D c->freelist;
> -               struct slab *flush_slab =3D c->slab;
> -
> -               c->slab =3D NULL;
> -               c->freelist =3D NULL;
> -               c->tid =3D next_tid(c->tid);
> -
> -               local_unlock_cpu_slab(s, flags);
> -
> -               if (unlikely(!allow_spin)) {
> -                       /* Reentrant slub cannot take locks, defer */
> -                       defer_deactivate_slab(flush_slab, flush_freelist)=
;
> -               } else {
> -                       deactivate_slab(s, flush_slab, flush_freelist);
> -               }
> +       if (allow_spin)
> +               goto new_objects;
>
> -               stat(s, CPUSLAB_FLUSH);
> +       /* This could cause an endless loop. Fail instead. */
> +       return NULL;
>
> -               goto retry_load_slab;
> -       }
> -       c->slab =3D slab;
> +success:
> +       if (kmem_cache_debug_flags(s, SLAB_STORE_USER))
> +               set_track(s, freelist, TRACK_ALLOC, addr, gfpflags);
>
> -       goto load_freelist;
> +       return freelist;
>  }
> +
>  /*
>   * We disallow kprobes in ___slab_alloc() to prevent reentrance
>   *
> @@ -4925,87 +4611,11 @@ static void *___slab_alloc(struct kmem_cache *s, =
gfp_t gfpflags, int node,
>   */
>  NOKPROBE_SYMBOL(___slab_alloc);
>
> -/*
> - * A wrapper for ___slab_alloc() for contexts where preemption is not ye=
t
> - * disabled. Compensates for possible cpu changes by refetching the per =
cpu area
> - * pointer.
> - */
> -static void *__slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node=
,
> -                         unsigned long addr, struct kmem_cache_cpu *c, u=
nsigned int orig_size)
> -{
> -       void *p;
> -
> -#ifdef CONFIG_PREEMPT_COUNT
> -       /*
> -        * We may have been preempted and rescheduled on a different
> -        * cpu before disabling preemption. Need to reload cpu area
> -        * pointer.
> -        */
> -       c =3D slub_get_cpu_ptr(s->cpu_slab);
> -#endif
> -       if (unlikely(!gfpflags_allow_spinning(gfpflags))) {
> -               if (local_lock_is_locked(&s->cpu_slab->lock)) {
> -                       /*
> -                        * EBUSY is an internal signal to kmalloc_nolock(=
) to
> -                        * retry a different bucket. It's not propagated
> -                        * to the caller.
> -                        */
> -                       p =3D ERR_PTR(-EBUSY);
> -                       goto out;
> -               }
> -       }
> -       p =3D ___slab_alloc(s, gfpflags, node, addr, c, orig_size);
> -out:
> -#ifdef CONFIG_PREEMPT_COUNT
> -       slub_put_cpu_ptr(s->cpu_slab);
> -#endif
> -       return p;
> -}
> -
>  static __always_inline void *__slab_alloc_node(struct kmem_cache *s,
>                 gfp_t gfpflags, int node, unsigned long addr, size_t orig=
_size)
>  {
> -       struct kmem_cache_cpu *c;
> -       struct slab *slab;
> -       unsigned long tid;
>         void *object;
>
> -redo:
> -       /*
> -        * Must read kmem_cache cpu data via this cpu ptr. Preemption is
> -        * enabled. We may switch back and forth between cpus while
> -        * reading from one cpu area. That does not matter as long
> -        * as we end up on the original cpu again when doing the cmpxchg.
> -        *
> -        * We must guarantee that tid and kmem_cache_cpu are retrieved on=
 the
> -        * same cpu. We read first the kmem_cache_cpu pointer and use it =
to read
> -        * the tid. If we are preempted and switched to another cpu betwe=
en the
> -        * two reads, it's OK as the two are still associated with the sa=
me cpu
> -        * and cmpxchg later will validate the cpu.
> -        */
> -       c =3D raw_cpu_ptr(s->cpu_slab);
> -       tid =3D READ_ONCE(c->tid);
> -
> -       /*
> -        * Irqless object alloc/free algorithm used here depends on seque=
nce
> -        * of fetching cpu_slab's data. tid should be fetched before anyt=
hing
> -        * on c to guarantee that object and slab associated with previou=
s tid
> -        * won't be used with current tid. If we fetch tid first, object =
and
> -        * slab could be one associated with next tid and our alloc/free
> -        * request will be failed. In this case, we will retry. So, no pr=
oblem.
> -        */
> -       barrier();
> -
> -       /*
> -        * The transaction ids are globally unique per cpu and per operat=
ion on
> -        * a per cpu queue. Thus they can be guarantee that the cmpxchg_d=
ouble
> -        * occurs on the right processor and that there was no operation =
on the
> -        * linked list in between.
> -        */
> -
> -       object =3D c->freelist;
> -       slab =3D c->slab;
> -
>  #ifdef CONFIG_NUMA
>         if (static_branch_unlikely(&strict_numa) &&
>                         node =3D=3D NUMA_NO_NODE) {
> @@ -5014,47 +4624,20 @@ static __always_inline void *__slab_alloc_node(st=
ruct kmem_cache *s,
>
>                 if (mpol) {
>                         /*
> -                        * Special BIND rule support. If existing slab
> +                        * Special BIND rule support. If the local node
>                          * is in permitted set then do not redirect
>                          * to a particular node.
>                          * Otherwise we apply the memory policy to get
>                          * the node we need to allocate on.
>                          */
> -                       if (mpol->mode !=3D MPOL_BIND || !slab ||
> -                                       !node_isset(slab_nid(slab), mpol-=
>nodes))
> -
> +                       if (mpol->mode !=3D MPOL_BIND ||
> +                                       !node_isset(numa_mem_id(), mpol->=
nodes))
>                                 node =3D mempolicy_slab_node();
>                 }
>         }
>  #endif
>
> -       if (!USE_LOCKLESS_FAST_PATH() ||
> -           unlikely(!object || !slab || !node_match(slab, node))) {
> -               object =3D __slab_alloc(s, gfpflags, node, addr, c, orig_=
size);
> -       } else {
> -               void *next_object =3D get_freepointer_safe(s, object);
> -
> -               /*
> -                * The cmpxchg will only match if there was no additional
> -                * operation and if we are on the right processor.
> -                *
> -                * The cmpxchg does the following atomically (without loc=
k
> -                * semantics!)
> -                * 1. Relocate first pointer to the current per cpu area.
> -                * 2. Verify that tid and freelist have not been changed
> -                * 3. If they were not changed replace tid and freelist
> -                *
> -                * Since this is without lock semantics the protection is=
 only
> -                * against code executing on this cpu *not* from access b=
y
> -                * other cpus.
> -                */
> -               if (unlikely(!__update_cpu_freelist_fast(s, object, next_=
object, tid))) {
> -                       note_cmpxchg_failure("slab_alloc", s, tid);
> -                       goto redo;
> -               }
> -               prefetch_freepointer(s, next_object);
> -               stat(s, ALLOC_FASTPATH);
> -       }
> +       object =3D ___slab_alloc(s, gfpflags, node, addr, orig_size);
>
>         return object;
>  }
> @@ -7711,62 +7294,25 @@ static inline
>  int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t si=
ze,
>                             void **p)
>  {
> -       struct kmem_cache_cpu *c;
> -       unsigned long irqflags;
>         int i;
>
>         /*
> -        * Drain objects in the per cpu slab, while disabling local
> -        * IRQs, which protects against PREEMPT and interrupts
> -        * handlers invoking normal fastpath.
> +        * TODO: this might be more efficient (if necessary) by reusing
> +        * __refill_objects()
>          */
> -       c =3D slub_get_cpu_ptr(s->cpu_slab);
> -       local_lock_irqsave(&s->cpu_slab->lock, irqflags);
> -
>         for (i =3D 0; i < size; i++) {
> -               void *object =3D c->freelist;
>
> -               if (unlikely(!object)) {
> -                       /*
> -                        * We may have removed an object from c->freelist=
 using
> -                        * the fastpath in the previous iteration; in tha=
t case,
> -                        * c->tid has not been bumped yet.
> -                        * Since ___slab_alloc() may reenable interrupts =
while
> -                        * allocating memory, we should bump c->tid now.
> -                        */
> -                       c->tid =3D next_tid(c->tid);
> +               p[i] =3D ___slab_alloc(s, flags, NUMA_NO_NODE, _RET_IP_,
> +                                    s->object_size);
> +               if (unlikely(!p[i]))
> +                       goto error;
>
> -                       local_unlock_irqrestore(&s->cpu_slab->lock, irqfl=
ags);
> -
> -                       /*
> -                        * Invoking slow path likely have side-effect
> -                        * of re-populating per CPU c->freelist
> -                        */
> -                       p[i] =3D ___slab_alloc(s, flags, NUMA_NO_NODE,
> -                                           _RET_IP_, c, s->object_size);
> -                       if (unlikely(!p[i]))
> -                               goto error;
> -
> -                       c =3D this_cpu_ptr(s->cpu_slab);
> -                       maybe_wipe_obj_freeptr(s, p[i]);
> -
> -                       local_lock_irqsave(&s->cpu_slab->lock, irqflags);
> -
> -                       continue; /* goto for-loop */
> -               }
> -               c->freelist =3D get_freepointer(s, object);
> -               p[i] =3D object;
>                 maybe_wipe_obj_freeptr(s, p[i]);
> -               stat(s, ALLOC_FASTPATH);
>         }
> -       c->tid =3D next_tid(c->tid);
> -       local_unlock_irqrestore(&s->cpu_slab->lock, irqflags);
> -       slub_put_cpu_ptr(s->cpu_slab);
>
>         return i;
>
>  error:
> -       slub_put_cpu_ptr(s->cpu_slab);
>         __kmem_cache_free_bulk(s, i, p);
>         return 0;
>
>
> --
> 2.52.0
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AJuCfpEEUs98yCiNA%3DQOPY6Qk7%3DQhSBF%2BgqPn5a%2BB%2BbYbQwvsQ%40mail.gmail.c=
om.
