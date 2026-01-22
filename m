Return-Path: <kasan-dev+bncBC7OD3FKWUERBPHKYXFQMGQEAX5FZ6I@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id AIbRET91cWm3HAAAu9opvQ
	(envelope-from <kasan-dev+bncBC7OD3FKWUERBPHKYXFQMGQEAX5FZ6I@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 01:54:23 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb137.google.com (mail-yx1-xb137.google.com [IPv6:2607:f8b0:4864:20::b137])
	by mail.lfdr.de (Postfix) with ESMTPS id 98105601C0
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 01:54:22 +0100 (CET)
Received: by mail-yx1-xb137.google.com with SMTP id 956f58d0204a3-64680de9f05sf969958d50.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 16:54:22 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769043261; cv=pass;
        d=google.com; s=arc-20240605;
        b=M8Xnys53s1Tbf7sW9OSCzj6CTkSZ6Popypa4f8vgKrk6Arr28A0pg3lGYGE7VNEUF0
         +041FPHHFdKUnzeULAllV/QH9vUDsmJnJrTuArjFDG4gZTDF6Q2BzSEx4zfSsLpV4RcC
         9xnOh23TxB87E0BBlxKdhVBEMlGss6Q26EuHOTExK4kLP+FG/gufe1yFv17Z/eh72anY
         siv+iP2jB1MvvDRgIvQkz+2bEPkDzw0vEsk7majIPiZyb4sNxO1wHPzN6Gr2ZIPz/OA7
         gHujyu6vOTXQFx6oDKAtJr4dcg5Yj5gm22xfnuVHLy7cQQe9lXkMQ0cu/4zBdiWstDwv
         +mkg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xBwHqkmX5GnlZAROp2NHNrkA+//GzpQ3+8czBebUa6g=;
        fh=kbxYxOSh0PGovzOYEGDkl/NKO5MLA7iyvpT8oQlew18=;
        b=FM4r1Se8glz0Ufi3BUVXydNN33hWTGfmVjV2rAXK6d6PV74rxZ91Bghkt0ZmABAX+Y
         SOYwYNkDFJ6wM4W9wv7POMJL+4fZF0THDuxSX9BTYOd2YL8EQHXjSxfGFURxzbGcyEly
         dtNzY3QKS1cC/jfRc98Yz0+4n7DQPRhCWqM/7Zn5q3/hzhrICTQQ7dXt458jgyn7oPvZ
         H5PJdmxRhg+gET6gs51vcooUWAXm5btclXx6nfbGJtwmnN/0DoAX7o+auu8XZwLtm4Hw
         q5687BdwZ+dYK7652dHvNa4GXbRGKyKyjZUI4j8YHi9XIGwAWLam5o0qjINRG6gMENMq
         bjkQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=CLw0b0oR;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::830 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769043261; x=1769648061; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xBwHqkmX5GnlZAROp2NHNrkA+//GzpQ3+8czBebUa6g=;
        b=MsuK3t/0fNxlSBwmj8/advy2twoWRWdIYhk7zcDryap129yDmRBCZcjk2WF4zp2+6c
         wlI9reFlBGYAGY4h9l3yCUqxy1yGINI99iW27i26FDWkMgnjPeGDKsdSZT/VqWoAJ0N2
         s52iktblWJsb5zT+p0ownBWHUW7w5+ko17upVn1QjRCb5gFhb0Ufb4nL5HpaUl3NlWLd
         m0z/LXyya/tHKRwAXD+O3BoK5wDpb4Zjh2qX3Xl6TaA1/wtliCNtYiM3EA5yDKxhLYKg
         aAcc1xNn8Hm3LWetZSIblWLxgSg83uJ9wdx+UJWDAdJtJS3X/VEfQvEweRP2XX+hcwlG
         LHeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769043261; x=1769648061;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=xBwHqkmX5GnlZAROp2NHNrkA+//GzpQ3+8czBebUa6g=;
        b=gOBiM4LGR1iRLwkO/XkzJ21sUZCaE3ecjaCB29+uByKMEBa5SjS9KHN7GR2pc+3I7M
         DSsngJ1gXGd34BNf2b4OyrR3Kx5EZKaoJIcOK8JfxoCTceu8aUTVD7idRIKNpF++3qcq
         zXwTK9fZcJ4V5YmiY/FI9/exbjq5bJ+1nk+j/fcJshEqSTakjkMBLqPaFj4Bt4WtRQIR
         FHD1+vIwjXw3F45IA7233+uSj5psRUC2Dn3Jr7eyEX7qVNr2/zh7DW3SxMKw+UmrYm0Q
         Alv99tHfeQJzKAd6pyXjx14GF62ITws0zje7aXAq8+zFDy8/02ipRklHSqKRJuRUUDQy
         xhVQ==
X-Forwarded-Encrypted: i=3; AJvYcCXqYs34PPlFC11KGfPJZp0g64tUN8rTug+PGmxiPhHZtAIL1P0P/FePQXjHiNZy+6/iNK2VCg==@lfdr.de
X-Gm-Message-State: AOJu0YxZQdfTO1OQoFWQhEnLya3lW9j+w3dCiSYurJY/NJ0RCD1bKHHa
	2g8nIb/QrufhCu9/k2uANy0FUI2pe4jvxUY73dXIwWvkRXwUAg5YbGKb
X-Received: by 2002:a05:690e:4183:b0:644:4259:9b64 with SMTP id 956f58d0204a3-6493c849223mr5447368d50.59.1769043261081;
        Wed, 21 Jan 2026 16:54:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EwHpHomgcL7CoBq+LdlWNnP5hpbOs2OlHmOR3Yq+D7tw=="
Received: by 2002:a05:690e:210:b0:644:6e7f:f254 with SMTP id
 956f58d0204a3-649513bc1a7ls278012d50.0.-pod-prod-07-us; Wed, 21 Jan 2026
 16:54:20 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVZxF10dSorST1T52HUR3qS8ZrncK41S8c4t1Wj1JNz3MgnMsiIrFyzltkIiwGw1+BnOmDQv4PceT0=@googlegroups.com
X-Received: by 2002:a05:690c:4d0a:b0:786:7017:9511 with SMTP id 00721157ae682-7940a122c2emr56945047b3.23.1769043260229;
        Wed, 21 Jan 2026 16:54:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769043260; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZjP0PLsqgL8oYbRzRYDAPgNQqVI3DbU1AYgC200RtzQDTlfDi3YRyLWHQaz14T4DVy
         YfNTNbLyhaLouds6y9syfUliRqa5LumdSERYTe8FFCpKNvPyKDj/KmQ5kWhiIpC8WDsl
         EFlvYirQl/8vr1/e6n/roNovJxlu2qsUSFPndKV/MtxyeYUqFG7Ysh6Yy7Pkie/4pNge
         uohi4xfY1gcwkl1XD2i8yaTs/Dijn46PAwDalf5lxOCgUiCnuGLiWU/jFF/xpyT+cQsQ
         ZalAhkB7/dPRJV4RGxribgGG7gd9XQ6D9IrGKpkCGV3QXHL457jOxcPfeSBqUynZc2Gs
         8BQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=+NqFR4vEi17NIt2eo657HYzQ+UfH+loYG1rnphf1kfI=;
        fh=dn+5fMpmDM0Xk4LqfMz8zTJfSnwJ+hXY9310ud8kV/s=;
        b=kjBlWQ+fH9sm4KG8Gs2YMNLcSREi13yCiQopKzTZeWLcjwhq82yR7oN8NQREyBZ7BB
         jifg4P7IMPmm72sKD3pbBfEMSoFBjjXYw/Xj4PhsLPmKYeBWyOlS57WfsZFL7NPdGXhD
         NvpPuUqQ5EfPqSLl0Mi34Xtc3ymdSqVGTBTcQaOETmaKtNsQSgOmhu5iec1lK0FVCspK
         WAwMgKq3m5QiGFAGfhIrYfDOHXi+nXWQeIo9LXGWs6AaHdvZkKsxUxMVWItY34sJuUQU
         5KWQh4XBrxLwVKbDEfSWcdIOheYDYZ8z1wZSUmrKAzTSvdvNrreTO+5+zL8S+roc2b6o
         QmNg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=CLw0b0oR;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::830 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x830.google.com (mail-qt1-x830.google.com. [2607:f8b0:4864:20::830])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-793c6835018si5816307b3.7.2026.01.21.16.54.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Jan 2026 16:54:20 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::830 as permitted sender) client-ip=2607:f8b0:4864:20::830;
Received: by mail-qt1-x830.google.com with SMTP id d75a77b69052e-50299648ae9so71101cf.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Jan 2026 16:54:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769043260; cv=none;
        d=google.com; s=arc-20240605;
        b=V3qX1yWztjmvwLK23d+1n0yZcc/8fXBWPl2Ip32DLG3GioCFTEmBO6psEqOrpIl/57
         XVz61dncsyx7M5mNDqXPtR1gMDAcTQATuMcS6bEsiueKdYd2LwlHIQPe1c5SoaecVu9R
         RLn5hzhS47YQaZjrquedkt/XhgwD4+RMscYGQDy6b4GPH9sJwlpDClTfWF+u5UC0MlFz
         fRQx1H3W7S5hJ0IpSV6a9gHOiCBQeELN8dVDZ/RxH/WqRFGovRYU9Qyqtn7OsDe0TNLo
         /OrBPLNWXLklYKDZnEv73AbJ/q3D9YVujz8HNYtm34etAg6sHwjJAbzUEa0jispqm+AK
         GdCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=+NqFR4vEi17NIt2eo657HYzQ+UfH+loYG1rnphf1kfI=;
        fh=dn+5fMpmDM0Xk4LqfMz8zTJfSnwJ+hXY9310ud8kV/s=;
        b=AyTLXsBRFOoUaZdXcq6XEZKZMvKCZZADvUmMOfwwt4FxJCOY/xOnbIDSKSfanwW3oh
         +8g+kY4RUvt17S6jwjytWh0FyjCmW5hIOpjBo+qJh45GLktAUh7LiSkSjW/FE9/BSqUW
         HtJolQ2eiZgRaYgGIXSYapowhS9RmCQU69LcjquvaNJHXF+cFv3C1DzwoBGLf4/+lPlJ
         Qt7HeOANrJyUZNeo6BEZQ4VIOGddxw8srvZzzkrK4f1N678wqLlrEQzbB614UvPICqVi
         Rrj49nfmaLNF5/Kbo8471iOLOs7jt3zn4qRMSZfxAREOtKoKWiZCX32TU+fwjr1HfGHm
         lYfw==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCUVsW4z40evfpYTU2e/V61slVcIerLEQmvsd/mihIPLwI9v1FgEznjq0DkHH5vgkDRaeM/N4tp1IVo=@googlegroups.com
X-Gm-Gg: AZuq6aLUnDjScnTKMtIps1Kb7ZbtdI1PPzrysCXfYpvXxQ6z8lm0sey/Wq1cx3/j4nz
	RM0gJO9LI84ekkPaiYGAqAEBk7hd2Lq/yC18isADUxb8P6cXTNdh/vZfUmjmgx7AsnNOco+7SX1
	QV3qV23y9lXEw2xRu0OjCroA8S8JexJbN1m9drsA7Gr9ru/OfIFFvgzV1HcObF2Oks7/mCfLBv3
	EI0vnQmdtLrnXP9/WKSEqUGsgrKfRgmVHHuGSWTV2yH+A5wZC48qaHxpVAdot/aU/G6E34Nj6X0
	VjVeFPi0bUeP1SN7kqp3rLizvA4vs6nQYA==
X-Received: by 2002:ac8:7f11:0:b0:501:3b94:bcae with SMTP id
 d75a77b69052e-502ebd67f28mr5244541cf.8.1769043259374; Wed, 21 Jan 2026
 16:54:19 -0800 (PST)
MIME-Version: 1.0
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz> <20260116-sheaves-for-all-v3-19-5595cb000772@suse.cz>
In-Reply-To: <20260116-sheaves-for-all-v3-19-5595cb000772@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 22 Jan 2026 00:54:08 +0000
X-Gm-Features: AZwV_QiKaqX658yaaNclaMUDJFMuWaWyjwe3fGXZJxanEvpjJyRl1f7lSqjnfpQ
Message-ID: <CAJuCfpHggP+iefwGTOWnSxDma5U=uMROYNs8KS0A=u2w=1rq_w@mail.gmail.com>
Subject: Re: [PATCH v3 19/21] slab: remove frozen slab checks from __slab_free()
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
 header.i=@google.com header.s=20230601 header.b=CLw0b0oR;       arc=pass
 (i=1);       spf=pass (google.com: domain of surenb@google.com designates
 2607:f8b0:4864:20::830 as permitted sender) smtp.mailfrom=surenb@google.com;
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC7OD3FKWUERBPHKYXFQMGQEAX5FZ6I];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail.gmail.com:mid,suse.cz:email]
X-Rspamd-Queue-Id: 98105601C0
X-Rspamd-Action: no action

On Fri, Jan 16, 2026 at 2:41=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> Currently slabs are only frozen after consistency checks failed. This
> can happen only in caches with debugging enabled, and those use
> free_to_partial_list() for freeing. The non-debug operation of
> __slab_free() can thus stop considering the frozen field, and we can
> remove the FREE_FROZEN stat.
>
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Functionally looks fine to me. Do we need to do something about the
UAPI breakage that removal of a sysfs node might cause?

Reviewed-by: Suren Baghdasaryan <surenb@google.com>

> ---
>  mm/slub.c | 22 ++++------------------
>  1 file changed, 4 insertions(+), 18 deletions(-)
>
> diff --git a/mm/slub.c b/mm/slub.c
> index 476a279f1a94..7ec7049c0ca5 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -333,7 +333,6 @@ enum stat_item {
>         FREE_RCU_SHEAF_FAIL,    /* Failed to free to a rcu_free sheaf */
>         FREE_FASTPATH,          /* Free to cpu slab */
>         FREE_SLOWPATH,          /* Freeing not to cpu slab */
> -       FREE_FROZEN,            /* Freeing to frozen slab */
>         FREE_ADD_PARTIAL,       /* Freeing moves slab to partial list */
>         FREE_REMOVE_PARTIAL,    /* Freeing removes last object */
>         ALLOC_FROM_PARTIAL,     /* Cpu slab acquired from node partial li=
st */
> @@ -5103,7 +5102,7 @@ static void __slab_free(struct kmem_cache *s, struc=
t slab *slab,
>                         unsigned long addr)
>
>  {
> -       bool was_frozen, was_full;
> +       bool was_full;
>         struct freelist_counters old, new;
>         struct kmem_cache_node *n =3D NULL;
>         unsigned long flags;
> @@ -5126,7 +5125,6 @@ static void __slab_free(struct kmem_cache *s, struc=
t slab *slab,
>                 old.counters =3D slab->counters;
>
>                 was_full =3D (old.freelist =3D=3D NULL);
> -               was_frozen =3D old.frozen;
>
>                 set_freepointer(s, tail, old.freelist);
>
> @@ -5139,7 +5137,7 @@ static void __slab_free(struct kmem_cache *s, struc=
t slab *slab,
>                  * to (due to not being full anymore) the partial list.
>                  * Unless it's frozen.
>                  */
> -               if ((!new.inuse || was_full) && !was_frozen) {
> +               if (!new.inuse || was_full) {
>
>                         n =3D get_node(s, slab_nid(slab));
>                         /*
> @@ -5158,20 +5156,10 @@ static void __slab_free(struct kmem_cache *s, str=
uct slab *slab,
>         } while (!slab_update_freelist(s, slab, &old, &new, "__slab_free"=
));
>
>         if (likely(!n)) {
> -
> -               if (likely(was_frozen)) {
> -                       /*
> -                        * The list lock was not taken therefore no list
> -                        * activity can be necessary.
> -                        */
> -                       stat(s, FREE_FROZEN);
> -               }
> -
>                 /*
> -                * In other cases we didn't take the list_lock because th=
e slab
> -                * was already on the partial list and will remain there.
> +                * We didn't take the list_lock because the slab was alre=
ady on
> +                * the partial list and will remain there.
>                  */
> -
>                 return;
>         }
>
> @@ -8721,7 +8709,6 @@ STAT_ATTR(FREE_RCU_SHEAF, free_rcu_sheaf);
>  STAT_ATTR(FREE_RCU_SHEAF_FAIL, free_rcu_sheaf_fail);
>  STAT_ATTR(FREE_FASTPATH, free_fastpath);
>  STAT_ATTR(FREE_SLOWPATH, free_slowpath);
> -STAT_ATTR(FREE_FROZEN, free_frozen);
>  STAT_ATTR(FREE_ADD_PARTIAL, free_add_partial);
>  STAT_ATTR(FREE_REMOVE_PARTIAL, free_remove_partial);
>  STAT_ATTR(ALLOC_FROM_PARTIAL, alloc_from_partial);
> @@ -8826,7 +8813,6 @@ static struct attribute *slab_attrs[] =3D {
>         &free_rcu_sheaf_fail_attr.attr,
>         &free_fastpath_attr.attr,
>         &free_slowpath_attr.attr,
> -       &free_frozen_attr.attr,
>         &free_add_partial_attr.attr,
>         &free_remove_partial_attr.attr,
>         &alloc_from_partial_attr.attr,
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
AJuCfpHggP%2BiefwGTOWnSxDma5U%3DuMROYNs8KS0A%3Du2w%3D1rq_w%40mail.gmail.com=
.
