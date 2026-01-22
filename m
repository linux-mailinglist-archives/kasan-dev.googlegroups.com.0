Return-Path: <kasan-dev+bncBAABBSW6Y3FQMGQEHIGGNRI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id oALZM0uvcWlmLQAAu9opvQ
	(envelope-from <kasan-dev+bncBAABBSW6Y3FQMGQEHIGGNRI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 06:02:03 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 72FEA61DF1
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 06:02:03 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-382fb514fdcsf2875281fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 21:02:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769058122; cv=pass;
        d=google.com; s=arc-20240605;
        b=F5K5wL+/Py4smcxohPY3irtbuVQQimNTR8SyCbF1h272YrcSJigXDKJWOOeHuWkAde
         b80QDBONbisUVO3342iaXVY0+VaOXF+rOex55KBKhD+cw8fCV9qdOdyUrtddqCkcSRye
         dWya5Z4InBdrbMNLgHBNMcfdiJhWdeQLJv60NFbi60NFXbw1fcATPokBMTr/2vc91nJO
         7Kam2dYvlL8fS/f0U8dTEv7XRfwgwdHchSdkvO++INJYhJHOFwtwhKD4WCEXIAkJecAZ
         ymtE7/fXu0d2v7rBl/hOJoS1ytrvFawb1b3csCNFkcqApvuJ1+agLHSYbADaiznSVDsp
         8lsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=nrbF7b8c9SALPbHdsjv/js/4v6qbyO6DpW69WSuSeMw=;
        fh=UFCys9dXEhXWEBneojpjygFAB4HN6msO5G6hnvHyhzk=;
        b=OyDhvpXo/zqJDqHaME2ndn32sYOg33b2U+jC2oKougp2LDdilYsR8LBr9JmJSjV5r9
         F3YcMAyXJKnNRL+lmNGoWCAUifnH8KRWfUQRlWpUxSYqr5ederVpCvW6ytkOrN/vPmHh
         7mmMV3Zj4Jhyr2IZu9sCW6VZeawLCwLK1aLmfYE8LSdX2+wcvewzXHJ6pUTcUj8gqnzP
         Z8YhXcM+4uIGjxDZ6J3x4DL4nWOI9C8s8DufhGHOScN2FG/WdQyGxgVYiF3nxIF38631
         CZl2zq7zsYCKOZHpgTkftlNThjNlCiyYP5HnJPygPmeXrgz4y2+mGherxc67AxjTghmm
         5GHg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qQl8IV6O;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::b5 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769058122; x=1769662922; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nrbF7b8c9SALPbHdsjv/js/4v6qbyO6DpW69WSuSeMw=;
        b=NRr6MHIrYxgVy50gwA7s+WrL2vNxYhdNMVjv1dHi4wrl5IueUn0jjGdrLxCPcyA5CA
         Om8TLhVTPcK9e+wfVFDBbKgeYPKTNqef9OJpkdp3m+OJ6hwMDlTCzwvP1cQ9ougufOfX
         nmkjdRwbV1FKHXNuDKThf8JtRe13shFmhewXGFVka9+R5YMWyR5hDs3J2heDS/7UtBIE
         6j+1nisrvX7IEcwMwdVMczQCtZybCxrx3KPHtogl+siZ6RH+YhVkE2iPU467yYn2q88L
         R/St4q0V+Xa7qFM7+vdAHPPz9uk+vyMiHq4zxT1DpCm2U46R1lEnm/1SEUGYlkunBqMC
         vZxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769058122; x=1769662922;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nrbF7b8c9SALPbHdsjv/js/4v6qbyO6DpW69WSuSeMw=;
        b=wxyojVQ0L3X+I7BoJpXiRMVjAfLOsznGks4U4pjRlBtWSbgMkL8GRF3Hv8oD28XG77
         hRhDV9SCWwMZFh9gWzT6hqRWri8Pv2Ue4vUmvyeSfPEhoEzzI5VF1kWZ3I7nLo6yyGPP
         QIxJoRnnnhaiaRlFZD51s6sLpFJ5ntALBcDzqjJgyGnOMzwKVD8PJWvNo26qmewWBS7g
         gpS2doSwuhb8PMx7ye7qJ1H62JpXe5/dfSKmpBj7FCGQlsBxSvrTlGlp3a8J6VJ1j1j2
         jN2+EFmwicisKQMiF45FNuA02kSXdbpnWYKWsDtgjIECPZrFnPxUmKg12+XMjtBCXnts
         Q0JA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUOVM+m2gCGu4/dq5ZtnIPl3vt94OYdDOWY/iDJl3Ctdl2IkeHPJVpY9DYaTUkHlFsgj2I+Kg==@lfdr.de
X-Gm-Message-State: AOJu0YwrErK/3VXvRmx3VLU6uN6X6s7NE2UrozhfOYQJFm7lrTvaI5t9
	UV06CKLMNHsAyeBsIjyhz1LWlIKpIFMtFjhp2Gk/TV2adC35Ag0H8Fxy
X-Received: by 2002:a05:651c:2112:b0:385:c213:4d0 with SMTP id 38308e7fff4ca-385c2131010mr6702001fa.33.1769058122551;
        Wed, 21 Jan 2026 21:02:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Eqh5WNPuhCucH8OHwEezVrs7DHgzbiISo+OLlBMnrNoQ=="
Received: by 2002:a2e:994b:0:b0:383:1a5f:713e with SMTP id 38308e7fff4ca-385c23692ddls442971fa.0.-pod-prod-09-eu;
 Wed, 21 Jan 2026 21:02:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXftohsMO71WhuNht/jXNk9RFTa42xdHa2AgFbm+V6phZS8UehuaurBA8D1G/paYA3OTWgs1zoXH0o=@googlegroups.com
X-Received: by 2002:a05:651c:2112:b0:385:c213:4d0 with SMTP id 38308e7fff4ca-385c2131010mr6701581fa.33.1769058120643;
        Wed, 21 Jan 2026 21:02:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769058120; cv=none;
        d=google.com; s=arc-20240605;
        b=P2axMa9yQCJ7O1jiSIXKAFl5HQaJX3ZLH/MCoJqtuvCprRA/qdMz0ZIDKQM09k2tf3
         2rVuK1yihfJgQ5PgqpZ7TUx6Am8Chm1ovbk4H2owo9kW5vgni0CgpKTW3czha+GY4Wm3
         BX7VeGoNgRqOtH/6PUtt0oPfw5YGst1ui2UPzd+sjzNhUfO09FKJW1yDEJojFSdM5gxO
         vCZBX16fFrc7QGFZB/rhENVtK5udfHSgqOBhxLcm/hQR1Q4pObVFFkZ05Zgic9FSoFlQ
         d96FCCyyJIWGj7xm87k2kGXsQ8LCbAPWK+YvE9kUrjuk5jRGCTaIjOGI8i1yqsrnprDC
         f69g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=nesrHAnPEf109FX2/lCNqfl81JEqewLyfAPoUShZzXI=;
        fh=2eNRZ9ECquILDe9T7DsfDKzbtYQIgOYM00xcI0sJ8bg=;
        b=YCEWrpWsW6Yqtm/yIi3GbOsYADOsVnnqVVt9Rq1rrtBtBFPye2pkmQ5t8MZ7L1TJDV
         9UF70faPR9IIQZ03L9zRcE1t2LA5j78+KfQ0mRbNFPWnCpfJwL0pI2IBsWuYB3n1p475
         9RdFVYUy2frE0m0q8jJFQ1xivfeUnRyfwSLxHcrsmnObpt1D7nJJRTOeKKU+s/Rd8F5y
         3Fv0WVY75lLGLPppaBiUjUVJEgB8wnj/bXwSpVUCI8XXZNH3KPgPz00Eb5ZIUkKzYHiL
         vujszpsZ0X0LcCIJYyVchwdocQV2ZmypS+K0gYIoTjkRPpSamdEASptHUKrAJrgWIGdk
         koig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qQl8IV6O;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::b5 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-181.mta1.migadu.com (out-181.mta1.migadu.com. [2001:41d0:203:375::b5])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384d35eabsi3286331fa.3.2026.01.21.21.02.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Jan 2026 21:02:00 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::b5 as permitted sender) client-ip=2001:41d0:203:375::b5;
Date: Thu, 22 Jan 2026 13:01:48 +0800
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Hao Li <hao.li@linux.dev>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Suren Baghdasaryan <surenb@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 19/21] slab: remove frozen slab checks from
 __slab_free()
Message-ID: <7syrsyflw6ii223mwyvnwz5pu7chlh5ddmblyq7izmgvtv4xt5@pl6osos5rpy7>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-19-5595cb000772@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-19-5595cb000772@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=qQl8IV6O;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::b5 as
 permitted sender) smtp.mailfrom=hao.li@linux.dev;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=linux.dev
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
X-Spamd-Result: default: False [-1.11 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MID_RHS_NOT_FQDN(0.50)[];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[linux.dev : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_COUNT_THREE(0.00)[3];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	RCVD_TLS_LAST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_NEQ_ENVFROM(0.00)[hao.li@linux.dev,kasan-dev@googlegroups.com];
	TAGGED_FROM(0.00)[bncBAABBSW6Y3FQMGQEHIGGNRI];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[linux.dev:email,googlegroups.com:email,googlegroups.com:dkim,suse.cz:email]
X-Rspamd-Queue-Id: 72FEA61DF1
X-Rspamd-Action: no action

On Fri, Jan 16, 2026 at 03:40:39PM +0100, Vlastimil Babka wrote:
> Currently slabs are only frozen after consistency checks failed. This
> can happen only in caches with debugging enabled, and those use
> free_to_partial_list() for freeing. The non-debug operation of
> __slab_free() can thus stop considering the frozen field, and we can
> remove the FREE_FROZEN stat.
> 
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 22 ++++------------------
>  1 file changed, 4 insertions(+), 18 deletions(-)
> 

Looks good to me.
Reviewed-by: Hao Li <hao.li@linux.dev>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7syrsyflw6ii223mwyvnwz5pu7chlh5ddmblyq7izmgvtv4xt5%40pl6osos5rpy7.
