Return-Path: <kasan-dev+bncBDTMJ55N44FBBVM3X7FQMGQEXCO4HCQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id kKIbINfNb2mgMQAAu9opvQ
	(envelope-from <kasan-dev+bncBDTMJ55N44FBBVM3X7FQMGQEXCO4HCQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 19:47:51 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 2763B49C39
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 19:47:51 +0100 (CET)
Received: by mail-qk1-x740.google.com with SMTP id af79cd13be357-8c52bb3ac7bsf942049185a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 10:47:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768934869; cv=pass;
        d=google.com; s=arc-20240605;
        b=OiFlfzCjzbOFJ50ee8oJ4PLD1GILr7v6xQiiIWkMyQ7rVWsz/sx2l1616RsSbe8I8X
         B4IroFG5UOC2KWszwOv3thgY/DOUgS3WtkrZURd4pnLxd/9yU9rhlmvBAFgeiGp96Se7
         JNsTYJ27d3say1rQuXA0nlTcDKtqOpxrFUIB4A78noxlpun77w8xQEqFACZINR0N24+a
         dCgMLqg5DCLqHh4vaH53WbamYEIrLLEbbUw9AQoaeGmYOi5fa7TuagDpR20ieZR0vO2/
         D/PWiXF8Qe6QwMG7FXjYIECfnBvoxM1LUrKkl93EhL0gxVW1NPAPEOa3Vcw5LcbPPItX
         okhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=IP9BkKzf4X8L2HCEkSmTKS+6hu8n4Cd3hyGLYlwCD8g=;
        fh=4DCLS3Uuw1naOuPV/q1uozS7vMvECdHdv28uqbF7NVE=;
        b=TXjQS2kQkceVE5NjMPDcgkYc1bC1RXCAwABPdGhWXOSAy8ynuyDcMHopwdzrgMWKE4
         y5okgKrnQhM8IwPq5f2j6s83qoGYSrF9R2omxc404wOyI4Sng2MbB8rgtSoI7DqHAv79
         reMu1LxT1X+ZrnF9U8YhKlcGjS/3D6+D15E4BuouzPykGo3KVglJUHWIecIW+KzbWhuG
         rd1FtkbvFXzdCkd2Nhi5ox1veTa0oa1DuBuCsqRXt1CvOTcU9VS4i3rrrJbxpUPIg5CW
         zabbrR99E9Z8zHaLy9eOdSQhm9Q+6mJERD6rRkGEosuxXL1HoMvOAhvy4XJyVjsbciGp
         ChDA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.210.53 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768934869; x=1769539669; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IP9BkKzf4X8L2HCEkSmTKS+6hu8n4Cd3hyGLYlwCD8g=;
        b=lh+g1p31PyTCkFm3quV9EWzOqJAbhoBMHCFKGSFTkuDLnGLv4gyqJsmwQ3cqXAAsiI
         kwdUJmepTnolGBH4FMy3JpyOBYE7VQGiKeq4s+YCq6SSCDi/rFHbtDz4OUWFnw6VKh2V
         +CrJkPuS/3lH/Cq4YFDcSh28E2/ficylwk/xGu/LO+p3IqIsk0X8CB/dAoqVe78YplKj
         n1GfSBGaOaY0fQSSSrn3YKOpr3g/enYLcVjbavvbPQpI1Qpa3dEjkOZgJDb3aLmyKV1f
         bO0srSdgX2ut+PNy7ZLpc0pIwW80N1kuAkEZhJYLam7D+iduKzTfUrOLa9omn0j5byT7
         Nw8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768934869; x=1769539669;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-gg:x-beenthere:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=IP9BkKzf4X8L2HCEkSmTKS+6hu8n4Cd3hyGLYlwCD8g=;
        b=ETHkjL/qjZXoGIyulU2w/NGjSCurdOJo6YPLcTODjewGSmuklhmDi9kbibftsH3dQD
         el7Sk2H5U6r/qasFIdcDhV2IfuEL5P2yJ5wPBFDkEhPZ+JkZxmBo2vKVezTe3Kfwdjv3
         u5e1nR/xJyLOiXYL513lqn3gLv2hvWVVM3/q/9rOc24r4EtHA6QmPR/44khKkDwx7Qes
         1yc2v93hAXKIQZwBhWGkhhbfVxAyasZH/EhzB9J4FHGW6tH5y8iJR1ZPNA//ZRsTiaCa
         8wpAEdfzyZT8TfpfXP36VWg8YT9RGnNJTUBn+Lz4m0Ri2Oq2w9Qeifw9np2eE2PGNN4f
         jmsw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVzQrMLLh+6VhtdFmL38sUs9TYztOsAdFnOyksSSpH3Bb1eOCYG3SqMPjXpMGKTW3aYfxS7IQ==@lfdr.de
X-Gm-Message-State: AOJu0Yzzx/L48XnYQCN0U/ZltXS+XjbhDSHls6tOx8ggN1mZ6Mu2a6ZB
	q+4WRkaWFyGhFWFhjYFEKjJFJtzAMcYmBmkpV0msygMugvT6nUAXAfzf
X-Received: by 2002:a05:620a:4495:b0:8b2:dd0a:8809 with SMTP id af79cd13be357-8c6cce6dfa1mr309568685a.89.1768934869680;
        Tue, 20 Jan 2026 10:47:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+ESPcKfgQOi+kvDy47DGSTe0u0Dnfm4AQJL2TtdLx351A=="
Received: by 2002:ad4:5dc7:0:b0:880:59ee:bbc with SMTP id 6a1803df08f44-894222f36c2ls134057656d6.1.-pod-prod-09-us;
 Tue, 20 Jan 2026 10:47:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWMPgaDvCc2C5opDb9GtFIeDItKJ30GYIAx63xM5MpiZaLn2dQPEWhMmgZ2KKLeP7A5aql7x0vVZ0E=@googlegroups.com
X-Received: by 2002:a05:6122:608a:b0:557:b52a:d553 with SMTP id 71dfb90a1353d-565de39b6edmr1021460e0c.7.1768934868552;
        Tue, 20 Jan 2026 10:47:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768934868; cv=none;
        d=google.com; s=arc-20240605;
        b=P3mphjUWysf5mlae6Fe7Vik+RKhFt3UTRqGEq7O+Dwoxf++iSdqZ8dYpVs6HgSxTOX
         VnT9WXV3QVfeVTIsz922Rw7mePzYB34cxvwSAxcokTPAXVHajErUU7DileHtzQOJIGAF
         jlH3/RK88ZNeIaDXrosJkhwScKEBz0SyEYiIEvJXHWDRvcVG1w/JxLSxfAjIriXNcsVs
         zSdHL4tmxP5HNGU23VohhaLfalT7JUOlHsvfxUGSrBNaSQOluu4/tcy1DIRhwgsE1X6K
         ulIVJaxAuMA8YJcYqR3KUBCd1i2rumfm1hVq+RVKu6nmAIe48kdSPRl1Mwkn7H2E63ZF
         jb9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=cyvv5bVOKq5q2ikgZwkotwgP6l+kB/mtu+tHV4I/d8o=;
        fh=ky2jgLjz7eAJmOD7uv33sGc87vqfLqvpspBCzr8S+7E=;
        b=ldEERBrnIPT6Vks8Cp7sWW8EdE+80DC1x9SWCQyGzmP6kOdejdG1y660LU0HitAGWn
         b+F6PoVoMwT+yuEB4GVBZV0pLD3gI1LMdYOr+ZzgLvn5/wL2tGJISzgna5QhKofi8Uah
         NE5UGN8iCZT1438AsYOVRnfAmjIF/CVtHK2DwWW6fflOXAD0+5rsM5wkKb9xEKFmYrr/
         cJymTmgBY9iwU0bhg2lBp8OFqtul3GUWNgWkmllVRif9USfcyLVV6ccrU8vpAaUrpVvM
         AphyIaeVAZofIDusDPVMB7pucTzgS5znP3vYLrSFfdEWPkbTbYmhbdmqt364CWS7+2X/
         DxjA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.210.53 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-ot1-f53.google.com (mail-ot1-f53.google.com. [209.85.210.53])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-563b716bcaasi422295e0c.8.2026.01.20.10.47.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jan 2026 10:47:48 -0800 (PST)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.210.53 as permitted sender) client-ip=209.85.210.53;
Received: by mail-ot1-f53.google.com with SMTP id 46e09a7af769-7cfcbe7d176so3618785a34.3
        for <kasan-dev@googlegroups.com>; Tue, 20 Jan 2026 10:47:48 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVmi0DB/rDwDOBiiPPAJrvoo4ajOU0itIPEBLXli6PH219FOaWdCGUQsXWMc9f0lmH8EBgx3mBwOCI=@googlegroups.com
X-Gm-Gg: AY/fxX7W1UbdMMggqTcQ+zvOSvZXmRY50DMleSCD8vc/fjFmF0MEac0K4Q7h4+WMLfN
	dH043Dx7n/U17lxePfyiIhyCodaSh5JDsQmx67OsdJWMIf1FZg6stvIcUQ+rRTb1yLkGvH4iFIt
	tAOdhXQWpBScAKRJWGaxAVaSWdxqj0NKjv+CqkadpjJHV26AvmCRAHEZ0Yle4x4NqaGUkPGTsff
	yD59TjAagNn76oTj3GIxJibJn4XMvU3Ss+1+CiUonGAfBK4dA8loxxctnEVc454XEHDOfSAJI5i
	iBpGQm2g3HkbX90k1ysRyqt3Aed1UFvXxOWNMkdGcndzkGYe6K/y8DtTwedVk5m7s0Fmx28/SZ8
	a4Vr9mmfXEwDKXpRB5wmFhO2mt5ZefbqDA1BfuvFM87NThVQlC1o1qdvpC/qwie7WPHdiw58IJX
	KlyQ==
X-Received: by 2002:a05:6830:3986:b0:7cf:da97:57d6 with SMTP id 46e09a7af769-7d140a3d3c9mr1655270a34.6.1768934867912;
        Tue, 20 Jan 2026 10:47:47 -0800 (PST)
Received: from gmail.com ([2a03:2880:10ff:52::])
        by smtp.gmail.com with ESMTPSA id 46e09a7af769-7cfdf0e956esm8985236a34.10.2026.01.20.10.47.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 10:47:47 -0800 (PST)
Date: Tue, 20 Jan 2026 10:47:45 -0800
From: Breno Leitao <leitao@debian.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>, 
	Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Suren Baghdasaryan <surenb@google.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, 
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 05/21] slab: add sheaves to most caches
Message-ID: <aW_NK2NXVgtuzCVH@gmail.com>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-5-5595cb000772@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-5-5595cb000772@suse.cz>
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.210.53 as
 permitted sender) smtp.mailfrom=breno.debian@gmail.com
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
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FROM_HAS_DN(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	DMARC_NA(0.00)[debian.org];
	FORGED_SENDER_MAILLIST(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TAGGED_FROM(0.00)[bncBDTMJ55N44FBBVM3X7FQMGQEXCO4HCQ];
	RCPT_COUNT_TWELVE(0.00)[18];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	MISSING_XM_UA(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_NEQ_ENVFROM(0.00)[leitao@debian.org,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail-qk1-x740.google.com:rdns,mail-qk1-x740.google.com:helo]
X-Rspamd-Queue-Id: 2763B49C39
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

Hello Vlastimil,

On Fri, Jan 16, 2026 at 03:40:25PM +0100, Vlastimil Babka wrote:
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -7863,6 +7863,48 @@ static void set_cpu_partial(struct kmem_cache *s)
>  #endif
>  }
>  
> +static unsigned int calculate_sheaf_capacity(struct kmem_cache *s,
> +					     struct kmem_cache_args *args)
> +
> +{
> +	unsigned int capacity;
> +	size_t size;
> +
> +
> +	if (IS_ENABLED(CONFIG_SLUB_TINY) || s->flags & SLAB_DEBUG_FLAGS)
> +		return 0;
> +
> +	/* bootstrap caches can't have sheaves for now */
> +	if (s->flags & SLAB_NO_OBJ_EXT)
> +		return 0;

I've been testing this on my arm64 environment with some debug patches,
and the machine became unbootable.

I am wondering if you should avoid SLAB_NOLEAKTRACE as well. I got the
impression it is hitting this infinite loop:

        -> slab allocation
          -> kmemleak_alloc()
            -> kmem_cache_alloc(object_cache)
              -> alloc_from_pcs() / __pcs_replace_empty_main()
                -> alloc_full_sheaf() -> kzalloc()
                  -> kmemleak_alloc()
                    -> ... (infinite recursion)


What about something as:

diff --git a/mm/slub.c b/mm/slub.c
index 26804859821a..0a6481aaa744 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -7445,8 +7445,13 @@ static unsigned int calculate_sheaf_capacity(struct kmem_cache *s,
        if (IS_ENABLED(CONFIG_SLUB_TINY) || s->flags & SLAB_DEBUG_FLAGS)
                return 0;

-       /* bootstrap caches can't have sheaves for now */
-       if (s->flags & SLAB_NO_OBJ_EXT)
+       /*
+        * bootstrap caches can't have sheaves for now (SLAB_NO_OBJ_EXT).
+        * SLAB_NOLEAKTRACE caches (e.g., kmemleak's object_cache) must not
+        * have sheaves to avoid recursion when sheaf allocation triggers
+        * kmemleak tracking.
+        */
+       if (s->flags & (SLAB_NO_OBJ_EXT | SLAB_NOLEAKTRACE))
                return 0;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aW_NK2NXVgtuzCVH%40gmail.com.
