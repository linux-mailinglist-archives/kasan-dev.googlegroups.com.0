Return-Path: <kasan-dev+bncBC7OD3FKWUERBFHWYPFQMGQES333OXA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id EJOODxf7cGmgbAAAu9opvQ
	(envelope-from <kasan-dev+bncBC7OD3FKWUERBFHWYPFQMGQES333OXA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 17:13:11 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A95459BF6
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 17:13:10 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-81f4c1412b8sf57262b3a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 08:13:10 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769011989; cv=pass;
        d=google.com; s=arc-20240605;
        b=PqIinoxxvr6g5mZJMTJuyh5EN04Tt5JByt5lOs60jvwkAz/YF1sGZeejcvZzgOm/V1
         O7timlwMu+wM3a6+UBYTi8nfxUH10zRIL1w+hhPBFfrCAEds8z1aWMDCqGQ3PT+5S7h8
         QF0dpJp30Nvboxmed4FZxhmlr2SvwVxG5DbWkLV9LnUvkk8X2IR1Lh1Hw3+N8miFcDhc
         5J0ygZwArW5sCC2XBPZqmRr/ivr7dLei8H1g9FLKK54bNE2fpsQN1OZ/G1+mjvK0kDbM
         C58IruYsFtan1Zi6xp5dMYPe22YkqauLSldOq9peAwS8bqHgumHAe4exZHWb0BbsLGjL
         Sq0g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aexUI7e0vDwXsDh/aaatBbuB5BNhYQPfTpko90/Z54o=;
        fh=ABMRIplZblmExyRC+oA8hNpzrdSpBFnvJbRVqYJTWr4=;
        b=jRt7rhp6IBR4OF1ImgxDBq6+sMoKFolqPzd2MntT60Y0unEGSRV59RCv4L4tpTm0mW
         R6v/24AK4VHRf6i/mXEJQW+4v6o4vrbbHEt6brH7NyEVH5mKx8btKIPmK0qwfF80AGpT
         M62ijgPoO2fVlz787+M/fRV/auSaVVIACvSu+hZ/a0C59WxcS0PWVKaYtueCIaZ6LuAu
         vVwxIbAHOEOGkjVkuGu7ydQKIPjJXtrXRSWbYc7n5lyhaw+W0uBpqGdtAcg76WFVr34Y
         MBuSC7SO06JWkBVdzH07G6IM7sPkgpJzuAWIL6QiiuTX3bUoyP+xfD1WGSw4jlBpApzu
         b9ZQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WFlYVZbl;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769011989; x=1769616789; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=aexUI7e0vDwXsDh/aaatBbuB5BNhYQPfTpko90/Z54o=;
        b=OoYUIZJPNBV6saqUXYONU9y/VFTsYjnhnKsTl/WvQ2W1oTjKy4AvQ2QkgM3MRytJKU
         qsIz/U5FGhVJCciUYt5QxBf3Uk7akLgXpkOYGVNedZaxXRIhjIyxgxIQqTUb0a1f/Ff3
         qG1sH5r9tpZeY17zpjSeFNtGLslyqbam35E4NhHkLUe8RtH1lHbE3y2D7gE86R8vIt14
         C7JBSXt+j+0zxfyX2q9intYdgO2BrmM1P9vue2n+/ZNDm3nGHB9NbLFX1xSmpN+L4tFz
         QIYiNavtp/DXWYGpAePoUgA4jo0ZyXiVJeIm0dhD2Nqkncbf0E3XdCKoxxbZbo/ekBhs
         2g/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769011989; x=1769616789;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=aexUI7e0vDwXsDh/aaatBbuB5BNhYQPfTpko90/Z54o=;
        b=A2nulPVB+wckFf3yggXSjrdV0NquOVJmktF20u05T7nU8I6FgbeyeT60BG8JGgGgsM
         tY/gTNx3ZcjuvsYO22DkZqkOPpyU9urmfSxLyvEZE+4lrKNDSAnwVQUN4yiKCTF7YhWn
         yfpSpwjchEXyynU9mBSoPOdVP6Gu3p8EdYuvOhU96+ftQer7fQFdZnVK5cv4eOeWRFho
         SenJJ1yGZeRiO2DONWj5J/D26Xaf5dyld0qShlgOGaC7/nS3LpQrdQ5y6I0gNmF+9DVv
         2yZMv1GE4c2BDPgsP9l53BwiDyHplEQ2DFU6izCfSqs+xJ5TGo/WuJtQ6K/kEYmeCu6W
         nsWA==
X-Forwarded-Encrypted: i=3; AJvYcCUdAYWRrSXnBZxA069Gg52NnBsWdorKX1wLaJgwDdn7KfwdEq6LZWtedEqFGTWBaoNdKlgX2g==@lfdr.de
X-Gm-Message-State: AOJu0YzEePG4zaLFI70Jjhs2Zf07wuxsbq/88FmPYIJVEGTZGLVu9FL8
	FaYc+P13ifGWCtQ8PwPJZ/cGeHg9rkGZ72pTsD821UR75QpgEJWf3tgy
X-Received: by 2002:a05:6a00:71c1:b0:81f:5678:cc04 with SMTP id d2e1a72fcca58-81fe8874189mr5010474b3a.32.1769011988815;
        Wed, 21 Jan 2026 08:13:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Hp2VOhNTU+emHGZPcgCair44LC3Wi0tKL8cet/vfoWtw=="
Received: by 2002:a05:6a00:2f18:b0:7a4:b41c:6e3f with SMTP id
 d2e1a72fcca58-81f8e6c9ba6ls2327906b3a.0.-pod-prod-08-us; Wed, 21 Jan 2026
 08:13:07 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVPK/wAG7/fCL24fRbeHxSZT6sWkivoSX+Qy1BUulU3v6iB9MKXlR+SIi/MrHGXvJRZlUl6DzHs7b4=@googlegroups.com
X-Received: by 2002:a05:6a00:a85:b0:81f:3cd5:206e with SMTP id d2e1a72fcca58-81fe87b2921mr5436815b3a.1.1769011987055;
        Wed, 21 Jan 2026 08:13:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769011987; cv=pass;
        d=google.com; s=arc-20240605;
        b=JTxmccHzu+gx+fCiBsOy5wEQnHCFbxxrifeB62tfPRvwywK9VyDooYnEta425hK3hF
         80+q1JEkQxF8czHjj/LX2UCfc7VwmWrxxbPqaTgVxFcmrUilRCe+VZ66cJfBH991ZFEM
         xmbbkR2c3FeFhVEcZ5x1/HWUEsnULqTdRrnXzt+KWRc+xecA9MsKKwvAqTYNRnnFPut1
         soySxEDGezenCD25H5dP0NHtfjHivlaGzu7qOujOWBwWtW6GsZkyF0q0lufYN2L0vdDX
         upELb9Z6+kdXjm1fE7UiDywX5j/8DN6llDwYNu6WEdUDouxJs+w8UUrXOrSlHGmrIDNo
         eKKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=y1GwHpmSY+Ssuo+YrlkBnP/wYaSl4q4+E3mKjKXYR/c=;
        fh=4E+SQlPnJcPznOCDm/ETUpVCThTrDB7eu5qYVj60O4g=;
        b=YZjrnWnesRtBSbeFMr9RgvVWmFFkHAezf+O0AU9e2tFefYaU+jmO1gQ7ZCJq4zJWk2
         zRsGXYEClptrekbdG1S69IDFEQvVnrNZG3MUvNxLlX6/n0piESFgdStjj7Ncu8Mk2uYO
         AXiNH8ADWkRAopoIZIaiY3t33j8vt5xRXfmXgY1qJCgN1HDxiLQeCI2AZ5uCG84pgun0
         cAcM2QQjyDd4hw9qzF7ZvfqYPV+6i76sgtJumorUKWZ2xLZ8Hi/pthb06i/9fF4IDnsK
         ME7Mz37jpBpvZ0EERDxgPAxnOG+CvuSC/PKO6F+sZSHH6e5gSCI03Jv64crikYTbeUAx
         OCzg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WFlYVZbl;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x833.google.com (mail-qt1-x833.google.com. [2607:f8b0:4864:20::833])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-81fa10899fdsi390272b3a.1.2026.01.21.08.13.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Jan 2026 08:13:07 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::833 as permitted sender) client-ip=2607:f8b0:4864:20::833;
Received: by mail-qt1-x833.google.com with SMTP id d75a77b69052e-5014acad6f2so88791cf.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Jan 2026 08:13:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769011986; cv=none;
        d=google.com; s=arc-20240605;
        b=KY375zQB8PKX7m6ufZCBAxhTbgwaLNx3kC3A6vzKSid/Fvz7cEMjcs9xoEuwkg03ud
         ykHqzhwCwED3m1B6g9NoCv5VPWQTINmSNi44s6Pi9ZKOZrVf9LyiWSGVN8ST9yvGtfOI
         NEM1Q4rjq461+e3XF8Geuvhl+YEh1hx5aBdbfcPhgBrrMY14+LMvtv3vkx6v10Jz1VAD
         9dPuhznGUHSAwOIUAbOkKxEYbKs2S8iFdJlA5JCO0slDraV/voyjbooLBPWfn1dtdG3Q
         TBodn4DTm6xNTj2GCurFnMfBmpcyS82HJfnSZIe2nFy1Lj4iE9uNFaMG8ofuWzNq4qk1
         NuFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=y1GwHpmSY+Ssuo+YrlkBnP/wYaSl4q4+E3mKjKXYR/c=;
        fh=4E+SQlPnJcPznOCDm/ETUpVCThTrDB7eu5qYVj60O4g=;
        b=MgWdCH+1jzk2Os+4DZtKLOJikBWLCWN7Bj+SRVc7fDdt5QHA7yqTZUmikzZG1oStDe
         dgIeOnpaittItUd2Ic1TNvwBFtWaEw0maoP2nzWDlj/JG9nSchRINH4IHF+0pSKP9bJZ
         8hSy1+VuJ8Pe3/PsGfbYgzzizx8mGY27tcLkwhj3ZxDhgPHv58JUiVo85z5IFp6DtOls
         np7xQTKvmbB4D3SnRb8x6Ep4WqmKy4JalLHH89UkUib+WW5SyrzyJlXrMF0NMM4gogkf
         GZOFNnZqtBwOfDEypnE/MNR7uQELKX45gX+oICNYRNEnPBFDsIICXzM1JLUCMe7K7WnB
         vdeg==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCVzwkO+dVsh6BtvJrHYSUldofe0kHuSVbxUa9FXsYGFXYEekDy5tt8hhfva1hrw0CK2Vr8IBjTOw84=@googlegroups.com
X-Gm-Gg: AZuq6aI+iEkvy+miX5amvB2tj0YK/AVud8Tuo3XozXXk79iGaAQP1UyuXBpxlPoaHT7
	tEO48+MoV6HxgpBC+MssC3RmsqWQQHwmagkY4T4XChk3nhQyXODa1hOFuy8DKLv3gvWUZFlYRLq
	rRcgf+IC/Yn6NmA9FdnXjIhaG3o9RpakcxilA/XdvK6srOWH4vaN4wY/lC90/18j+a4UqKmrVan
	jCSYXXmk/EYM2wcbIzTwOVbqit51uohj8ZkXFd0Fcyxa1Oqovhu5KfYg9ZBUZEiSI1CEnIHu/AP
	hLtv4XG3N5ccTuGhhVlWTnioORlrA38e/A==
X-Received: by 2002:a05:622a:1888:b0:4fb:e3b0:aae6 with SMTP id
 d75a77b69052e-502e1a18978mr11594511cf.1.1769011985614; Wed, 21 Jan 2026
 08:13:05 -0800 (PST)
MIME-Version: 1.0
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-9-5595cb000772@suse.cz> <CAJuCfpErRjMi2aCCThHiS1F_LvaXjkVQvX9kJjqrpw8YnXoNBA@mail.gmail.com>
 <fec4ed92-32e1-4618-99d6-0eac77da1ff3@suse.cz>
In-Reply-To: <fec4ed92-32e1-4618-99d6-0eac77da1ff3@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 21 Jan 2026 16:12:54 +0000
X-Gm-Features: AZwV_QiSjzEmuwsWdtzV6KlI2OJ4fFRrfgPi7_dAQ80cVBUvpM4Z4I7qS0kyx9I
Message-ID: <CAJuCfpFzZnbZBX84xTTtTHmKebVxWXUXjFe5AQRTGnu-9AnRLA@mail.gmail.com>
Subject: Re: [PATCH v3 09/21] slab: add optimized sheaf refill from partial list
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
 header.i=@google.com header.s=20230601 header.b=WFlYVZbl;       arc=pass
 (i=1);       spf=pass (google.com: domain of surenb@google.com designates
 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=surenb@google.com;
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
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC7OD3FKWUERBFHWYPFQMGQES333OXA];
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
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,googlegroups.com:email,googlegroups.com:dkim,mail-pf1-x440.google.com:rdns,mail-pf1-x440.google.com:helo]
X-Rspamd-Queue-Id: 9A95459BF6
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Wed, Jan 21, 2026 at 1:22=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 1/20/26 18:19, Suren Baghdasaryan wrote:
> > On Fri, Jan 16, 2026 at 2:40=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz=
> wrote:
> >>
> >> At this point we have sheaves enabled for all caches, but their refill
> >> is done via __kmem_cache_alloc_bulk() which relies on cpu (partial)
> >> slabs - now a redundant caching layer that we are about to remove.
> >>
> >> The refill will thus be done from slabs on the node partial list.
> >> Introduce new functions that can do that in an optimized way as it's
> >> easier than modifying the __kmem_cache_alloc_bulk() call chain.
> >>
> >> Extend struct partial_context so it can return a list of slabs from th=
e
> >> partial list with the sum of free objects in them within the requested
> >> min and max.
> >>
> >> Introduce get_partial_node_bulk() that removes the slabs from freelist
> >> and returns them in the list.
> >>
> >> Introduce get_freelist_nofreeze() which grabs the freelist without
> >> freezing the slab.
> >>
> >> Introduce alloc_from_new_slab() which can allocate multiple objects fr=
om
> >> a newly allocated slab where we don't need to synchronize with freeing=
.
> >> In some aspects it's similar to alloc_single_from_new_slab() but assum=
es
> >> the cache is a non-debug one so it can avoid some actions.
> >>
> >> Introduce __refill_objects() that uses the functions above to fill an
> >> array of objects. It has to handle the possibility that the slabs will
> >> contain more objects that were requested, due to concurrent freeing of
> >> objects to those slabs. When no more slabs on partial lists are
> >> available, it will allocate new slabs. It is intended to be only used
> >> in context where spinning is allowed, so add a WARN_ON_ONCE check ther=
e.
> >>
> >> Finally, switch refill_sheaf() to use __refill_objects(). Sheaves are
> >> only refilled from contexts that allow spinning, or even blocking.
> >>
> >
> > Some nits, but otherwise LGTM.
> > Reviewed-by: Suren Baghdasaryan <surenb@google.com>
>
> Thanks.
>
> >
> > From the above code it seems like you are trying to get at least
> > pc->min_objects and as close as possible to the pc->max_objects
> > without exceeding it (with a possibility that we will exceed both
> > min_objects and max_objects in one step). Is that indeed the intent?
> > Because otherwise could could simplify these conditions to stop once
> > you crossed pc->min_objects.
>
> Yeah see my reply to Harry, it's for future tuning.

Ok.

>
> >> +       if (slab->freelist) {
> >
> > nit: It's a bit subtle that the checks for slab->freelist here and the
> > earlier one for ((slab->objects - slab->inuse) > count) are
> > effectively equivalent. That's because this is a new slab and objects
> > can't be freed into it concurrently. I would feel better if both
> > checks were explicitly the same, like having "bool extra_objs =3D
> > (slab->objects - slab->inuse) > count;" and use it for both checks.
> > But this is minor, so feel free to ignore.
>
> OK, doing this for your and Hao Li's comment:

Sounds good. Thanks!

>
> diff --git a/mm/slub.c b/mm/slub.c
> index d6fde1d60ae9..015bdef11eb6 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -4505,7 +4505,7 @@ static inline void *get_freelist(struct kmem_cache =
*s, struct slab *slab)
>   * Assumes the slab is isolated from node partial list and not frozen.
>   *
>   * Assumes this is performed only for caches without debugging so we
> - * don't need to worry about adding the slab to the full list
> + * don't need to worry about adding the slab to the full list.
>   */
>  static inline void *get_freelist_nofreeze(struct kmem_cache *s, struct s=
lab *slab)
>  {
> @@ -4569,10 +4569,17 @@ static unsigned int alloc_from_new_slab(struct km=
em_cache *s, struct slab *slab,
>  {
>         unsigned int allocated =3D 0;
>         struct kmem_cache_node *n;
> +       bool needs_add_partial;
>         unsigned long flags;
>         void *object;
>
> -       if (!allow_spin && (slab->objects - slab->inuse) > count) {
> +       /*
> +        * Are we going to put the slab on the partial list?
> +        * Note slab->inuse is 0 on a new slab.
> +        */
> +       needs_add_partial =3D (slab->objects > count);
> +
> +       if (!allow_spin && needs_add_partial) {
>
>                 n =3D get_node(s, slab_nid(slab));
>
> @@ -4594,7 +4601,7 @@ static unsigned int alloc_from_new_slab(struct kmem=
_cache *s, struct slab *slab,
>         }
>         slab->freelist =3D object;
>
> -       if (slab->freelist) {
> +       if (needs_add_partial) {
>
>                 if (allow_spin) {
>                         n =3D get_node(s, slab_nid(slab));
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AJuCfpFzZnbZBX84xTTtTHmKebVxWXUXjFe5AQRTGnu-9AnRLA%40mail.gmail.com.
