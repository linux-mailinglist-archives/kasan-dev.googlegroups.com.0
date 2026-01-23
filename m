Return-Path: <kasan-dev+bncBCKLNNXAXYFBB66GZXFQMGQEUNPTMNI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id gJiVOH1jc2mivQAAu9opvQ
	(envelope-from <kasan-dev+bncBCKLNNXAXYFBB66GZXFQMGQEUNPTMNI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 13:03:09 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B39775847
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 13:03:09 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-385d15481e2sf10335261fa.3
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 04:03:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769169788; cv=pass;
        d=google.com; s=arc-20240605;
        b=O+dvc0eU8TFOT5rjFFo/8jQOTj8tLnbLrSdjyx3s1dHkULCeqTSXeIZG/vxmglg+WI
         gyAAR7B6yNLPjlOvjohJr/60NV4LwhHkhnoUu0k1gABIMg9pzomgNpFeJbOzbbBk0ruL
         gdQxdGePHVz8ovEE5x9OX4L91hZ2aeCjyLvSeJLcAMEUyFIHqGMLp0UBn0qPd/+paLKs
         UpvnvZYhO+F1ldqsBD5OADQATY6lJ6KLCb3ge4JmmQ52tSC958UXX1HRHhAApLPQmEN5
         sys9GlTz6n9fWgjmm/XHgDIeFHtdtNW+XF4i9OlPTsr3r9PymgU2BjtC/mH6SsyaJDdj
         fSeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=+i0bpq5v/YTeYVAhqLOhij6x9G36oNCEHzrbAi44ES0=;
        fh=rL8A23yBRzHI2kVhp/JYNyc67BTXn8VI/+WqMJjvZAI=;
        b=f+O4LffYwv/K6WlqmN5SCA13XQ4IkXEHnQZI8sao23bV/fWKpnm/x29RGAlxHCs1Xn
         qUKoBeQgZmRHGH4s8VBqv2OlEXik6m5M185bj1fgL92xwzvJtrp9GdQlaeY7ZDGEo0Z9
         1Fv0iobDNTp9nOzFbJdHWTApOzWFCW1SKDk2t1j/RNtsIgJ0QqtcJ/iULi2q5l1JRLR9
         jfA9uEyyNniaLaBvJ1l9TasyH5Bjjwk8sGocqYrmNa046vXUxo50xs6lj244qKYFKL+F
         mm2gJVdtKR9Tsv6GuKkIOKwOjt78Dy08PtntwBhAPkEqDUm/sDbW+odQ/B+eLsw3pgia
         bk+w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=a2TXmIgH;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769169788; x=1769774588; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+i0bpq5v/YTeYVAhqLOhij6x9G36oNCEHzrbAi44ES0=;
        b=IDu9qWpz9yo+8QIv1+FYu8u9n/LFt5HToJvU9s98C7q6Y5ag43Mzgl92FmlzyCU0GD
         qkaff9ZBK2aL4bQYfii2n7aM5k/zSIqIk/SVmqv+bYzqTabJveZPImv62rqAITjfvBvU
         lBwHLzWEh6F/2QM6bPHHofDIm7meekbS+WbLVYydWvcRQKwh9TMzJJ8tQcJE78G1HwjH
         36v7oHqNOAC6pHib3oZuFsGY6O5d7DbR6rc/BRiBWbTIH5n+MZioFVWGMypbTzkwU7YW
         uTfC0ky05IqlzhXH9jCplttc1VPsAEDZVT9t2vfRpQVmiU0VDxwMt6iNXTbIUcyFhw6O
         jkkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769169788; x=1769774588;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+i0bpq5v/YTeYVAhqLOhij6x9G36oNCEHzrbAi44ES0=;
        b=af/8NwYTTG6ImCmPBDsedl16yQ7RN1ckYB5oqzyjQ+HWvUgIGOmKOGFhhZ87J01Buu
         Z246FRwU6PAj1/BXKygaj1WB6YR0ypBRDFhLIzMpC9BaLHEG2ZQUoWpTH9WwAcFHHRky
         o6+AU7bXD4vYAsbg7tzTlmBcSeUlJW9lbiFAGdnzmLwNTm7TnX+eJKCWPpCDVu7cveRM
         qj/rGkTmtdxzpygEIoIj//+lY05KGkijYE5qFLZkb4w402TAYuBWFYjDVM7IsLmVtxl5
         TDtIcEEzn0GWRMZ6s7ckAdlOi+RkmxKKhDLYMWIuKKn4fz2VqzXCvfdbAQhYpZoBBk1z
         Ff0A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV6wH9c+blNC/8AAKdKUnhHgP1JDLb6VuopKr77wPhWml+7PP4BZpxQkSrU3JgOAG+NLmeXQQ==@lfdr.de
X-Gm-Message-State: AOJu0Yxes60eF068yX9ouirZGQYSa6rehnJaZml3Lnq/fJx+Lenpj4Mb
	SyHiNql3IZiR9uXv16kYVRMoplmUeHDmrl3PlfLs56QwgV9Qk7/hxxVV
X-Received: by 2002:ac2:568c:0:b0:59d:e306:1d06 with SMTP id 2adb3069b0e04-59de816c154mr404007e87.36.1769169788368;
        Fri, 23 Jan 2026 04:03:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FAOTxf3DUEcCjv6iY/THQrvP3Jvfkzon22HLKq8n4gNA=="
Received: by 2002:a05:6512:2313:b0:59b:a3bb:9e0f with SMTP id
 2adb3069b0e04-59dd797f506ls753957e87.2.-pod-prod-01-eu; Fri, 23 Jan 2026
 04:03:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCULmpZOqqYdyD95xqoxC5jpcrON7U7v99ef94mWXZvD8uUti+YtVtXSLHEO7y06pZld4kaD2GMoY7c=@googlegroups.com
X-Received: by 2002:a05:6512:b84:b0:598:8f92:c33e with SMTP id 2adb3069b0e04-59de8177795mr423996e87.50.1769169785127;
        Fri, 23 Jan 2026 04:03:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769169785; cv=none;
        d=google.com; s=arc-20240605;
        b=Dn2cce4wB6AmBMYNk1Q+OrTRDqFeF8dSyxpfn5PAqvy58Q+73GW6cUkEMWFuOmlyrB
         n+NJlz36t3sntEqsuy9kBuX4/UC+OGaPMcFvS/nHcsPHgXnUjKBVop8hrcLz5nFgpWza
         cXwrvusCEP6ZfYfXhJJSURf3vZPys9EfMAICPg4VFwb0vFvhjAigSIhcwoDVvhrhejxf
         f1FuVKUH9h8se1M5RmSEEYYeVAVhZpiCe8keBOsIQMybyLp3++w/HYo4ENLDgLHgqKah
         +jLaed2tB5pmHsAyirNiHM2ayZVYnEtPxyGoQZI7SCStM5wLV9rNbECYGZpKzqmLtxFm
         Mf/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:dkim-signature:date;
        bh=d/X5EsI0mvP/S5uf20Pvy9T65z0CIjEe5oCCyfrYy4k=;
        fh=+mGKlXFggqqmsYs+NW4V9Erw0UAa/huPGc8yxCV90zs=;
        b=EblmHyEyAmgjQ4CPGjqV9236I5+frf8rB4t9XF0D4Nct+MZ4dzxrC9k8HPrSmie8ze
         1Tz2zncs1SkISW44jWKj3Y/Y4v8tIAppdgBWv4mUl0Obk02uepgCu+PyBqbIfQpZ1niz
         hVkGMY/SIa/0QMX6Wo/IRJkirBlP+U9+djvD1PTywmfbMMz+fQ9InDta6MQ0g2SJVNMi
         L5qZbt5/MW8Q2CCMgM5yuYSRWzCnigOIf/vtIYIQIDP6r28fvLc9dHBmimzUBmom1sx9
         HUe4z1WB00osrtXF/zoIR9+4+F2qCHdAgh0RuzbUGrEjdjw1XxGXDtwTflTJwfX4vDmW
         Mmjg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=a2TXmIgH;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59de490f1c6si43836e87.5.2026.01.23.04.03.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 23 Jan 2026 04:03:05 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Fri, 23 Jan 2026 13:03:02 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>,
	Christoph Lameter <cl@gentwo.org>,
	David Rientjes <rientjes@google.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hao Li <hao.li@linux.dev>,
	Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Suren Baghdasaryan <surenb@google.com>,
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
	bpf@vger.kernel.org, kasan-dev@googlegroups.com,
	"Paul E. McKenney" <paulmck@kernel.org>
Subject: Re: [PATCH v4 02/22] mm/slab: fix false lockdep warning in
 __kfree_rcu_sheaf()
Message-ID: <20260123120302.TsiVMAQb@linutronix.de>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <20260123-sheaves-for-all-v4-2-041323d506f7@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20260123-sheaves-for-all-v4-2-041323d506f7@suse.cz>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=a2TXmIgH;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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
X-Spamd-Result: default: False [-1.61 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[linutronix.de : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	TAGGED_FROM(0.00)[bncBCKLNNXAXYFBB66GZXFQMGQEUNPTMNI];
	RCVD_COUNT_THREE(0.00)[3];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	MISSING_XM_UA(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-0.942];
	FROM_NEQ_ENVFROM(0.00)[bigeasy@linutronix.de,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	MID_RHS_MATCH_FROM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	RCPT_COUNT_TWELVE(0.00)[18];
	TO_DN_SOME(0.00)[]
X-Rspamd-Queue-Id: 5B39775847
X-Rspamd-Action: no action

On 2026-01-23 07:52:40 [+0100], Vlastimil Babka wrote:
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -6268,11 +6268,26 @@ static void rcu_free_sheaf(struct rcu_head *head)
=E2=80=A6
> +static DEFINE_WAIT_OVERRIDE_MAP(kfree_rcu_sheaf_map, LD_WAIT_CONFIG);
> +
>  bool __kfree_rcu_sheaf(struct kmem_cache *s, void *obj)
>  {
>  	struct slub_percpu_sheaves *pcs;
>  	struct slab_sheaf *rcu_sheaf;

Would it work to have here something like
	BUG_ON(IS_ENABLED(CONFIG_PREEMPT_RT));

or WARN_ON+return? The way the code is now it relies on the check in
kvfree_call_rcu() and tells lockdep to be quiet. And since it gets
optimized away=E2=80=A6

> +	lock_map_acquire_try(&kfree_rcu_sheaf_map);
> +

Reviewed-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>

Sebastian

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0260123120302.TsiVMAQb%40linutronix.de.
