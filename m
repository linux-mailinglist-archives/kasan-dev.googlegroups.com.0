Return-Path: <kasan-dev+bncBC7OD3FKWUERBAX4YTFQMGQEC52PYFI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id GEJGIwU+cWnKfQAAu9opvQ
	(envelope-from <kasan-dev+bncBC7OD3FKWUERBAX4YTFQMGQEC52PYFI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 21:58:45 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-dl1-x1240.google.com (mail-dl1-x1240.google.com [IPv6:2607:f8b0:4864:20::1240])
	by mail.lfdr.de (Postfix) with ESMTPS id DF1D55DB66
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 21:58:44 +0100 (CET)
Received: by mail-dl1-x1240.google.com with SMTP id a92af1059eb24-124627fc58dsf609440c88.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 12:58:44 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769029123; cv=pass;
        d=google.com; s=arc-20240605;
        b=fvW/lknqsrYdxb2lXtLAmsrmQs2uBMtT4oScQOlIW5YLaQT2DaWX9sKkrplSu5sH9K
         CwquhTF5fDEZN3vspFbDxVZEgqSFeThGdPYYJaVGvVArWVxmzmoizwSgFDLbYwyWmtpw
         CB/FbI3n41qXD46HznNpA1Z0xF+o4sgq14Q53YilLHACsKmjrzb05LQlVZwCjv2h+Hh8
         pprRolMG7L81xF4Q5Jcjf5fAD/B9ad9sCS9YM8rFceusks5iArDnz50/XfXlQSKkTWPW
         /T5h0YiVSRP9femnugMsoGuQ8I+lpEBVIw6LxC3Vk3MuIgM9DkE68JwZt3nYA7aC8BOz
         4kUQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5ZMJwqwRT5UQufUxUYXG8lBl4sPOgzJpG6Tafio9SC0=;
        fh=q1uy4l/T5pM0sTJFmLq0+0Rurg5qgQ2lmN6UAS935gs=;
        b=hjb6pzOMNrK1lMsBbxTZ4XddswfHZFpKcxQ695vmrQllfnOlLi6y7o0frq1ZV9Ts/0
         i+Ys9WL3jS6ANdnPiuh9CbVv8H54DrioSxOvi4ecHlke3dAKWESAIW/8P46kUahXdCF9
         9wjjV/eXCTYDkn+ymmHRTOFpWBeEz1ibcPiVjtOXToLMEB5XGslbGbWHqP+WMajREQYG
         b7QMwmtv+gXrXwpK/UXb9TBNMoOHBEnSVtCg3uDLcwsSeEtrR5uDUselEkGMHhGH8L9h
         QNKl0sEow9GRh+gxkh+fO3y3kBo7ZSq7trIi6AX5fB/kXKskrLmD/C4Y9hAE/g8T9P6C
         Kybw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zi7qk0a0;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769029123; x=1769633923; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5ZMJwqwRT5UQufUxUYXG8lBl4sPOgzJpG6Tafio9SC0=;
        b=KiyI0k6UGlHF8K6InfibmpUDDIH7Rfl1Z+pRy6QWqZP84OupGQObi0/j5HiO0OFMW9
         Nj0lKkQ2qY8HSCCjmmYSrqbQiGo138iqdYBfjt9119Yo2hdgEfOBKvHqkgqB0/karD4c
         /gVSjF09pxXj5+beBF1vDzj9vp/XPhjBpOnpw4JEzVi1C2Yqi/MCm8whIy7YqTdvTOuo
         cSdOJ58X+liFULG29cXSM9ZwsxbFI9fSIqmjlPogmoaDxnjpgmLLVfeD8nL2ZEDujjh/
         0IWYzCyi7fgVY2uzLZ2vAUzL0XhJn+FyBW7uigbPjiuMhcil2cNw81J+/qIG3ch7DNAl
         +M0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769029123; x=1769633923;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=5ZMJwqwRT5UQufUxUYXG8lBl4sPOgzJpG6Tafio9SC0=;
        b=FHHCYxiMkgozx5jt2sL/Qga5F64c+SS+z1SK0WNFnvDa61horcJaPfvscI8btHgHmR
         3pkAWOR8trRsJVNA6r/J49mTHOriGHuX1dafY4p5rJtcvaq6lvEFz1HdIAmpYsU9wI0Y
         4cCJNshneZuqTFxW+ngm9TFtsvvTTW5Q3FSxK8c/onGkreAG1j00+R/Fw2T9rndAazIi
         rN3jRQMgwboOQ1nXrk1SaOO1GwMhJRRxK4F2IIwXJ2tnRokaRjlp8W4o5XlJeE7WUDpy
         X3IDMZ4WYQraCVv+zFe3zftvIXNj3vjCXkZKXe3fTzVL+7iq68YdoE8A0kbx7LsZ8fJY
         Qe1w==
X-Forwarded-Encrypted: i=3; AJvYcCUFfcp1QMMPwx+5j2NYRUGQTDAtRXidM3SLn2mcmQ2nqUng6JnhGHQWXGRPulx16lJolUsYkA==@lfdr.de
X-Gm-Message-State: AOJu0Yyr1aYPE4Uz68Z5otsL638L7d9S9TZYODlfYzX0Xt9yiySAsuB2
	DFSz+psdKaJ7iYipYBbrmw3GPSu+n6XEzoDRivK0egmg3aHHYe4xq6Iq
X-Received: by 2002:a05:7022:eac8:b0:123:35c4:f39c with SMTP id a92af1059eb24-1246aab35b8mr4498204c88.26.1769029122534;
        Wed, 21 Jan 2026 12:58:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HxnG5vU2ZRrHLz7OCwt/L1FMzAWOFnpgeYQcIAmabv9w=="
Received: by 2002:a05:7022:b056:10b0:123:395a:54bb with SMTP id
 a92af1059eb24-12476ca730fls128838c88.1.-pod-prod-07-us; Wed, 21 Jan 2026
 12:58:41 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWUKZ9bE+tZlwWV8/FRRJhKYlu2kzL4DbcdvpaCs8GCBy1oQmJSH6qU9m4EbpWsSqPRa2AwYynOHHw=@googlegroups.com
X-Received: by 2002:a05:7022:eb47:10b0:11b:a892:80a5 with SMTP id a92af1059eb24-1246a9683ddmr3805008c88.13.1769029120878;
        Wed, 21 Jan 2026 12:58:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769029120; cv=pass;
        d=google.com; s=arc-20240605;
        b=JJt2MV+awPwZY8XcKp/CMdp/6ben8ANB7ariIkuHg5AePBWjVr6N69WoUfXMRGL2eN
         8pbrGGi//b1/tPyHijkShVY37rO4r3n6zkcVT2QNYYNBMI1Xx9HjwgsDQ5i03ufrgZW6
         tHUiGN3ty1jOCDNJZiusF2lcBG8YdWwYkIxVOpsPN83iODyN0b5b/H0elfsyNPUR18Yn
         Ytvi2J7PUbQuOMI6SbHWLNr8YvOSS+oVx+REGmWeMplY5W9V0CFocbjG48PWAlwpBnVH
         cTK2bww85wE/NyZAgi0yDr/VomYzMnuF5hkEUnFReEs2SavhG5bUNFuW4/7htSHpmkEz
         MWVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=9MeTYXI3uAiRssw+rn1c1/h9gP0ELwUJeF0lPi9KAVw=;
        fh=os1fRdBJh6juT5z+2VTas3RHAe+9piN5X3DnipcGTT4=;
        b=h3gM11XY1cIpA3T5sk4thVtZuXdWouqviLpzQ2MpcuydPeRCttodVeWg1+nGSiiv6T
         zFgDQ+JCOGWlzfpU3H7XFVrGU6p2mbwDKqUtwpnx6VlrYqA/B9Vv+WXqgX0VM9YcJNSt
         zNCgrE7zcStzaUUv7bSN0QY8S+Iizg9p6NXXc0FfxCnwwjvHoyFQy/U1vY/o/aw23SQm
         29Hpz7n8+yRK6ASG7XrbFhMhdb+yDavUXRtOR6iQpARMcdL+xPBOSpSgJzxH7SOrJPbw
         szJiNnOBXoU0jVyYXkgK2ihPBgsQcwE0BxO8v+SOzukI42HvkzTCuBvWZFlxHCH68vkc
         yigg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zi7qk0a0;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x833.google.com (mail-qt1-x833.google.com. [2607:f8b0:4864:20::833])
        by gmr-mx.google.com with ESMTPS id a92af1059eb24-12457602350si387257c88.3.2026.01.21.12.58.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Jan 2026 12:58:40 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::833 as permitted sender) client-ip=2607:f8b0:4864:20::833;
Received: by mail-qt1-x833.google.com with SMTP id d75a77b69052e-5014b5d8551so126641cf.0
        for <kasan-dev@googlegroups.com>; Wed, 21 Jan 2026 12:58:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769029120; cv=none;
        d=google.com; s=arc-20240605;
        b=kBVpc+nb4xLkCQmjzSZHw0hqvB7WVzQWhkT9MDi0B+ZTbXCRb2kh360wZck2LIW2VK
         +Fa/xAqgmbRYaj1haKUjb176T9z2A++PYC0VCxIoOSpYi/3S/OcNdefcM6zLCP3fTE9f
         XFkjV5jYxX+aPhMiqzWQQgE+zzfpROibNK/aiFjirr/XfCrR1gaS25X8U/3pyoZ3kuUw
         vTS7Ob2tY0FVbe+MNLzGFwsD2XgrMKcidqyr5PkpfswYhhjMKMdreZ/aer3g/r+8K9Re
         4e7PAmXcex30I48bWpb1M8BUbA2lQOgrcY0PsXZvO73K/mNW/EdceD8VNcaT+HzRoB0b
         uauA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=9MeTYXI3uAiRssw+rn1c1/h9gP0ELwUJeF0lPi9KAVw=;
        fh=os1fRdBJh6juT5z+2VTas3RHAe+9piN5X3DnipcGTT4=;
        b=EoreF9HKvzLMtJUFvdQqzQB3rQStsvo4PXJ67Re9jEgbHQKnmgSadI3+ULBVEsJqqb
         ZjcLbF9HZwyZR82AgKPIeLS6Mtndqn9BSZC4N3JHFjCK0Nh0h1pqdvz/TGkZwUXMGONg
         /X9N+/4QP2muO6mEEbkjnXLckJ8Pe9wrYmn2RmJ+HocViGIKyElySZhqAugZN17fTR3I
         DwKOwD5Lqno09dCcwYGy2sAtOhLJ3J4AY7gGpNLMh5dmgDGTEO4kxt+CaBY9kWGAeUY1
         ZV6DAHPtgcbcCeC/1/68LIL+A+NNakx6poSa9ocos45PunXnOa1G73tgBQ1VdnN4LLii
         8ipg==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCVVnanTxN7nfVAdSnDe/mDMYIh1WXnmmdY4CG6HoEb4ewLvRAo1JGRZCiZhR12iqhkiba8Xyvf27Tw=@googlegroups.com
X-Gm-Gg: AZuq6aL779Rw96KPE0gGyi2I26xnJp/PgyctOv1KtUrwoY6HGoHv6DIO0hUvit67+fn
	4iTOW14tiM9xfy2CGgAfw+GgmxRRvt/SRIioNlrD8tFDvi02SAu5PpajgYtIwVQVkkRVT2hsXbr
	wI4Kf3q4CzAuG2GmQDfGlzPWqSbHY6iIWer11lp+i4OWk1lz+5QyqN/phqg2yZD8akzL8Ok5Lv8
	btQLWBkMr/FtzWr6BXHNSiNnIPqyevT+sqz29M7uGZUeVmk6iZhi7gFilP75m6jhLjAqFuKHkT1
	/1Au3qATAXiIsGaFueRsQOY=
X-Received: by 2002:ac8:7d13:0:b0:4f3:5474:3cb9 with SMTP id
 d75a77b69052e-502ebd66753mr2584691cf.14.1769029119662; Wed, 21 Jan 2026
 12:58:39 -0800 (PST)
MIME-Version: 1.0
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz> <20260116-sheaves-for-all-v3-18-5595cb000772@suse.cz>
In-Reply-To: <20260116-sheaves-for-all-v3-18-5595cb000772@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 21 Jan 2026 20:58:27 +0000
X-Gm-Features: AZwV_QgyZJFEnbtAO31t9RJqeLgp-_C0IEAaScaHgOZ1k_x7UdBOLV4hvrPmpf8
Message-ID: <CAJuCfpHZ5xJwg8uvK4XJ1+oBuNYQv3XMO8LHt9eEj_tJE=WkpA@mail.gmail.com>
Subject: Re: [PATCH v3 18/21] slab: update overview comments
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
 header.i=@google.com header.s=20230601 header.b=zi7qk0a0;       arc=pass
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
	TAGGED_FROM(0.00)[bncBC7OD3FKWUERBAX4YTFQMGQEC52PYFI];
	RCVD_COUNT_THREE(0.00)[4];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[surenb@google.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,suse.cz:email,googlegroups.com:email,googlegroups.com:dkim,mail-dl1-x1240.google.com:rdns,mail-dl1-x1240.google.com:helo]
X-Rspamd-Queue-Id: DF1D55DB66
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Fri, Jan 16, 2026 at 2:41=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> The changes related to sheaves made the description of locking and other
> details outdated. Update it to reflect current state.
>
> Also add a new copyright line due to major changes.
>
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Suren Baghdasaryan <surenb@google.com>

> ---
>  mm/slub.c | 141 +++++++++++++++++++++++++++++---------------------------=
------
>  1 file changed, 67 insertions(+), 74 deletions(-)
>
> diff --git a/mm/slub.c b/mm/slub.c
> index 2c522d2bf547..476a279f1a94 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -1,13 +1,15 @@
>  // SPDX-License-Identifier: GPL-2.0
>  /*
> - * SLUB: A slab allocator that limits cache line use instead of queuing
> - * objects in per cpu and per node lists.
> + * SLUB: A slab allocator with low overhead percpu array caches and most=
ly
> + * lockless freeing of objects to slabs in the slowpath.
>   *
> - * The allocator synchronizes using per slab locks or atomic operations
> - * and only uses a centralized lock to manage a pool of partial slabs.
> + * The allocator synchronizes using spin_trylock for percpu arrays in th=
e
> + * fastpath, and cmpxchg_double (or bit spinlock) for slowpath freeing.
> + * Uses a centralized lock to manage a pool of partial slabs.
>   *
>   * (C) 2007 SGI, Christoph Lameter
>   * (C) 2011 Linux Foundation, Christoph Lameter
> + * (C) 2025 SUSE, Vlastimil Babka
>   */
>
>  #include <linux/mm.h>
> @@ -53,11 +55,13 @@
>
>  /*
>   * Lock order:
> - *   1. slab_mutex (Global Mutex)
> - *   2. node->list_lock (Spinlock)
> - *   3. kmem_cache->cpu_slab->lock (Local lock)
> - *   4. slab_lock(slab) (Only on some arches)
> - *   5. object_map_lock (Only for debugging)
> + *   0.  cpu_hotplug_lock
> + *   1.  slab_mutex (Global Mutex)
> + *   2a. kmem_cache->cpu_sheaves->lock (Local trylock)
> + *   2b. node->barn->lock (Spinlock)
> + *   2c. node->list_lock (Spinlock)
> + *   3.  slab_lock(slab) (Only on some arches)
> + *   4.  object_map_lock (Only for debugging)
>   *
>   *   slab_mutex
>   *
> @@ -78,31 +82,38 @@
>   *     C. slab->objects        -> Number of objects in slab
>   *     D. slab->frozen         -> frozen state
>   *
> - *   Frozen slabs
> + *   SL_partial slabs
> + *
> + *   Slabs on node partial list have at least one free object. A limited=
 number
> + *   of slabs on the list can be fully free (slab->inuse =3D=3D 0), unti=
l we start
> + *   discarding them. These slabs are marked with SL_partial, and the fl=
ag is
> + *   cleared while removing them, usually to grab their freelist afterwa=
rds.
> + *   This clearing also exempts them from list management. Please see
> + *   __slab_free() for more details.
>   *
> - *   If a slab is frozen then it is exempt from list management. It is
> - *   the cpu slab which is actively allocated from by the processor that
> - *   froze it and it is not on any list. The processor that froze the
> - *   slab is the one who can perform list operations on the slab. Other
> - *   processors may put objects onto the freelist but the processor that
> - *   froze the slab is the only one that can retrieve the objects from t=
he
> - *   slab's freelist.
> + *   Full slabs
>   *
> - *   CPU partial slabs
> + *   For caches without debugging enabled, full slabs (slab->inuse =3D=
=3D
> + *   slab->objects and slab->freelist =3D=3D NULL) are not placed on any=
 list.
> + *   The __slab_free() freeing the first object from such a slab will pl=
ace
> + *   it on the partial list. Caches with debugging enabled place such sl=
ab
> + *   on the full list and use different allocation and freeing paths.
> + *
> + *   Frozen slabs
>   *
> - *   The partially empty slabs cached on the CPU partial list are used
> - *   for performance reasons, which speeds up the allocation process.
> - *   These slabs are not frozen, but are also exempt from list managemen=
t,
> - *   by clearing the SL_partial flag when moving out of the node
> - *   partial list. Please see __slab_free() for more details.
> + *   If a slab is frozen then it is exempt from list management. It is u=
sed to
> + *   indicate a slab that has failed consistency checks and thus cannot =
be
> + *   allocated from anymore - it is also marked as full. Any previously
> + *   allocated objects will be simply leaked upon freeing instead of att=
empting
> + *   to modify the potentially corrupted freelist and metadata.
>   *
>   *   To sum up, the current scheme is:
> - *   - node partial slab: SL_partial && !frozen
> - *   - cpu partial slab: !SL_partial && !frozen
> - *   - cpu slab: !SL_partial && frozen
> - *   - full slab: !SL_partial && !frozen
> + *   - node partial slab:            SL_partial && !full && !frozen
> + *   - taken off partial list:      !SL_partial && !full && !frozen
> + *   - full slab, not on any list:  !SL_partial &&  full && !frozen
> + *   - frozen due to inconsistency: !SL_partial &&  full &&  frozen
>   *
> - *   list_lock
> + *   node->list_lock (spinlock)
>   *
>   *   The list_lock protects the partial and full list on each node and
>   *   the partial slab counter. If taken then no new slabs may be added o=
r
> @@ -112,47 +123,46 @@
>   *
>   *   The list_lock is a centralized lock and thus we avoid taking it as
>   *   much as possible. As long as SLUB does not have to handle partial
> - *   slabs, operations can continue without any centralized lock. F.e.
> - *   allocating a long series of objects that fill up slabs does not req=
uire
> - *   the list lock.
> + *   slabs, operations can continue without any centralized lock.
>   *
>   *   For debug caches, all allocations are forced to go through a list_l=
ock
>   *   protected region to serialize against concurrent validation.
>   *
> - *   cpu_slab->lock local lock
> + *   cpu_sheaves->lock (local_trylock)
>   *
> - *   This locks protect slowpath manipulation of all kmem_cache_cpu fiel=
ds
> - *   except the stat counters. This is a percpu structure manipulated on=
ly by
> - *   the local cpu, so the lock protects against being preempted or inte=
rrupted
> - *   by an irq. Fast path operations rely on lockless operations instead=
.
> + *   This lock protects fastpath operations on the percpu sheaves. On !R=
T it
> + *   only disables preemption and does no atomic operations. As long as =
the main
> + *   or spare sheaf can handle the allocation or free, there is no other
> + *   overhead.
>   *
> - *   On PREEMPT_RT, the local lock neither disables interrupts nor preem=
ption
> - *   which means the lockless fastpath cannot be used as it might interf=
ere with
> - *   an in-progress slow path operations. In this case the local lock is=
 always
> - *   taken but it still utilizes the freelist for the common operations.
> + *   node->barn->lock (spinlock)
>   *
> - *   lockless fastpaths
> + *   This lock protects the operations on per-NUMA-node barn. It can qui=
ckly
> + *   serve an empty or full sheaf if available, and avoid more expensive=
 refill
> + *   or flush operation.
>   *
> - *   The fast path allocation (slab_alloc_node()) and freeing (do_slab_f=
ree())
> - *   are fully lockless when satisfied from the percpu slab (and when
> - *   cmpxchg_double is possible to use, otherwise slab_lock is taken).
> - *   They also don't disable preemption or migration or irqs. They rely =
on
> - *   the transaction id (tid) field to detect being preempted or moved t=
o
> - *   another cpu.
> + *   Lockless freeing
> + *
> + *   Objects may have to be freed to their slabs when they are from a re=
mote
> + *   node (where we want to avoid filling local sheaves with remote obje=
cts)
> + *   or when there are too many full sheaves. On architectures supportin=
g
> + *   cmpxchg_double this is done by a lockless update of slab's freelist=
 and
> + *   counters, otherwise slab_lock is taken. This only needs to take the
> + *   list_lock if it's a first free to a full slab, or when there are to=
o many
> + *   fully free slabs and some need to be discarded.
>   *
>   *   irq, preemption, migration considerations
>   *
> - *   Interrupts are disabled as part of list_lock or local_lock operatio=
ns, or
> + *   Interrupts are disabled as part of list_lock or barn lock operation=
s, or
>   *   around the slab_lock operation, in order to make the slab allocator=
 safe
>   *   to use in the context of an irq.
> + *   Preemption is disabled as part of local_trylock operations.
> + *   kmalloc_nolock() and kfree_nolock() are safe in NMI context but see
> + *   their limitations.
>   *
> - *   In addition, preemption (or migration on PREEMPT_RT) is disabled in=
 the
> - *   allocation slowpath, bulk allocation, and put_cpu_partial(), so tha=
t the
> - *   local cpu doesn't change in the process and e.g. the kmem_cache_cpu=
 pointer
> - *   doesn't have to be revalidated in each section protected by the loc=
al lock.
> - *
> - * SLUB assigns one slab for allocation to each processor.
> - * Allocations only occur from these slabs called cpu slabs.
> + * SLUB assigns two object arrays called sheaves for caching allocation =
and

s/allocation/allocations

> + * frees on each cpu, with a NUMA node shared barn for balancing between=
 cpus.
> + * Allocations and frees are primarily served from these sheaves.
>   *
>   * Slabs with free elements are kept on a partial list and during regula=
r
>   * operations no list for full slabs is used. If an object in a full sla=
b is
> @@ -160,25 +170,8 @@
>   * We track full slabs for debugging purposes though because otherwise w=
e
>   * cannot scan all objects.
>   *
> - * Slabs are freed when they become empty. Teardown and setup is
> - * minimal so we rely on the page allocators per cpu caches for
> - * fast frees and allocs.
> - *
> - * slab->frozen                The slab is frozen and exempt from list p=
rocessing.
> - *                     This means that the slab is dedicated to a purpos=
e
> - *                     such as satisfying allocations for a specific
> - *                     processor. Objects may be freed in the slab while
> - *                     it is frozen but slab_free will then skip the usu=
al
> - *                     list operations. It is up to the processor holdin=
g
> - *                     the slab to integrate the slab into the slab list=
s
> - *                     when the slab is no longer needed.
> - *
> - *                     One use of this flag is to mark slabs that are
> - *                     used for allocations. Then such a slab becomes a =
cpu
> - *                     slab. The cpu slab may be equipped with an additi=
onal
> - *                     freelist that allows lockless access to
> - *                     free objects in addition to the regular freelist
> - *                     that requires the slab lock.
> + * Slabs are freed when they become empty. Teardown and setup is minimal=
 so we
> + * rely on the page allocators per cpu caches for fast frees and allocs.
>   *
>   * SLAB_DEBUG_FLAGS    Slab requires special handling due to debug
>   *                     options set. This moves slab handling out of
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
AJuCfpHZ5xJwg8uvK4XJ1%2BoBuNYQv3XMO8LHt9eEj_tJE%3DWkpA%40mail.gmail.com.
