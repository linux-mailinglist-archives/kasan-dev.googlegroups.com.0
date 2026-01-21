Return-Path: <kasan-dev+bncBC7OD3FKWUERBYH2YPFQMGQE4XGP4II@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id qFS2JGL9cGmgbAAAu9opvQ
	(envelope-from <kasan-dev+bncBC7OD3FKWUERBYH2YPFQMGQE4XGP4II@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 17:22:58 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 215E059D43
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 17:22:58 +0100 (CET)
Received: by mail-ot1-x340.google.com with SMTP id 46e09a7af769-7cfd866fbefsf4885a34.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 08:22:58 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769012576; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ow/fmGwvHwn+4MdJTk9eHxGJEbq5pmdp08kLFMXdluFHvW8ECpxrU9ersxRmOtSwP3
         FUfv4yY07ZXveFqPPWg50CIoMYQIqble6HkkhPlIg8WIAzzPxsDrsACbYURNwrnLh2le
         oGQEWweVqp3zOkUm7hnRIyA96prUQxfAIkCXHNSB357jig7vTYnW+ab79AIGbQqar6dd
         KGt7CVyriez7DNfz1AkcYuU54GwXlMMZ7uHqBXcsbl6a4dofUvKkseNvZxdUgiklazHy
         CZ1EtFbvTGWKJagWsOMTZ/HeBgd3Mi/3qJsroarX2Ho7acObZ99hj+61diN9LPF9lpsS
         Iflw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=U0bEFEgOXOTO9aeaI6QwIruyZfW8MTi0xE+D1x5qTac=;
        fh=mFnjVWqY4qTVdU5I3v9YSwQfROAHTds+tzGvqtcFd/c=;
        b=bgLiw6mm3nK4bMI9jABsZVm02KevJmDuTO4HjDiBbERX9A2sxNJWKpHTfCNrSCdtIc
         i31mENatCll1E5b/h0YbnhTUmvZcO3OcY94YhzvzxeIzeCq419DqMU/WxTFrYKiiBS6X
         YZigrOTQ1btQOR5mbsLV+lr5j2NQc1EqXHg6YRG8uaSvEz9fGxP67JOedPrfnvA7rDV+
         iCc+3cZAdBnb3vMcOG/3lx9VWzP7LFwaX5V65zc+p+iuIVtW1qSBfMZvdyJ6Y0HGIjnc
         et4YqVN3LSADV0G/X0MsQtGZfIshAINOraOaesGfLoMoHIfm5lKU8BuS8df7o68+4v8U
         y1eg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="nsAY/czb";
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769012576; x=1769617376; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=U0bEFEgOXOTO9aeaI6QwIruyZfW8MTi0xE+D1x5qTac=;
        b=O9TY4m6zr5TmdIsIb6TokuX8AO9h55Hdj0jeZRe3QaSmUetEob8Iq+enGQLp9ZjuE5
         BVoURauoPMxXhcGwUZJzLh/SKxboJJsE3dSWcsE5tikOaynpPHBDIjKG3dYFNZvBRyis
         rg17o6ZYZrvEWXWIEHwfzuWJqNb7K71pxw4K2SbMokUR+JnVjeBhDBPZNyKBXXR5tpqR
         3AmQnkEsUSjKYBJ5Yr5+REjPnlKV8B7UESyrvgYbGpundvhmQbYojGUnRLezJ3CJWQV9
         qPl1HHuqjKPV1PL/PO+lc1tlFvlrdQgngLwA8qxqpoKtmxqAo2mvG2oO1TCw1rua+kDx
         ayjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769012576; x=1769617376;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=U0bEFEgOXOTO9aeaI6QwIruyZfW8MTi0xE+D1x5qTac=;
        b=bmpuFrm13NsyAU6zUN9W2ZUCVsXgHF0XiZYFq5uhSM+0PYgWRIvLGslJuxLGw18Stv
         163vQRwP5jE/RGPiybwatG9xKwiUYNEX8NJlRekyLkE1XXyE8UBtyeAXcaxbtxElDa3d
         CqB2IO/CX+FiIgebnAAeuIDu0JxqtEtpHSbOVOxn7RJw54MI8deeR+3DpPePMa/7v+zl
         l5BUrmhjO6tFOuAuFZhKs96wFmr8o+c/bSArcFlw2hvhZ0W9ufYryVPaf9F6+OB69oBr
         TFuKpl1BjhwjNy8GA5CbUlGxeYprtF+q1oz8kvoX9o5ZFRQaQ68SSC6E2/ajfb05DfY0
         lg5A==
X-Forwarded-Encrypted: i=3; AJvYcCUM7b9CAfJzLODBxGvAQ5o5kmYV6AoqhNNWMHoqEkTfTWDTKbUmf0hjkLK4Ve0fvRWKmytO8w==@lfdr.de
X-Gm-Message-State: AOJu0Yzp+zgAsxTzttXq7V3WgXfPsMcwOwyIlPSZfa2h7+Ie81QWZrA2
	zwqi/AiV+EPwLwebROOYmOfXtEpC7IQDoZRNhkU+KhqNhjdUU37132C+
X-Received: by 2002:a05:6830:4386:b0:7d1:4671:6f58 with SMTP id 46e09a7af769-7d146717212mr1870887a34.2.1769012576455;
        Wed, 21 Jan 2026 08:22:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Fvtgzg0XXH4GwWRstar2KHy0Taqb5WL8985Vt8EKZqXQ=="
Received: by 2002:a05:6871:3403:b0:3ec:406d:5582 with SMTP id
 586e51a60fabf-408825fdc22ls6517fac.2.-pod-prod-04-us; Wed, 21 Jan 2026
 08:22:55 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWhJGWLVmTNSKKiATvg9/4pHd5kz5QuROjSQrbrjBImUKhMON4R39aJDk7lHEhRslhMhlZdZ2vP29A=@googlegroups.com
X-Received: by 2002:a05:6870:a490:b0:3ec:4954:a8dd with SMTP id 586e51a60fabf-4044cf8f0acmr7502412fac.27.1769012575311;
        Wed, 21 Jan 2026 08:22:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769012575; cv=pass;
        d=google.com; s=arc-20240605;
        b=ax0tlYvQr6Fr2Y3thWptV3wvp544uCjum5gG17heF+iJiz5YM94s90TioEuEJ/h6YO
         PMKMhrHjrSKP3BwR6Z9u0XjdsvRMF07Cwu5dSEQb68TU29gIzpBqeBTh4AvaL3hbDWXg
         H1XVbL9vtyfOTTdTDw0ISrfGO0kLSecEL0CvJChl7ihjrpOidvVqazrekDOarD41sbF8
         YVi04nNboN2HawYixPOPnGHio+aJWiEDL4QLnrFOX3TblDQc8VKSug3HFwUl4UyGDw5U
         ueNS0T555bdr9jaAYtzt/U3sGTuExwwCpGOYWBgAHXiQ1cwOYws6k4Q8k1RXHg4a7EEt
         8EPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=zZKKP+4IZYFDaCDFilC88QfoYGNpM2dFv0WidsWIKI4=;
        fh=SmdH6JDaPvZaj0XLi4l1ENnA5W8xShS0wi8pvunvtWQ=;
        b=IT8n9pjBiNqYx1RH4AOp+TVQKFJVlCL1M7+F03oZUvICqU9yDYfnNG3OqfakCqH6GV
         SkGFcEe76kdKtk9xH5FP3By2mhZ6mxCF6M14gVNupjlVCehnbI/bGIeuiaNAOcTLrhnA
         lz5ZjP8ALbd1JwrZ8i3iDdGZb1lGscdX/0CE7RgGtjRCnCIIMVUN9djvNzj46RcXpF/y
         HKeMaen25mW6l3hgMycX242fGBQLajbpTBk8giOJys0v05YJhFZCptgXQTWvU49ACJLH
         2OCJcOptbXUhYlM9+7khRozeI4cpyNnp3kyb8PIfmbauwYs4Tf8D3psjvUYkgMebXsRI
         ORYg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="nsAY/czb";
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x82d.google.com (mail-qt1-x82d.google.com. [2607:f8b0:4864:20::82d])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-4044bc895casi446305fac.4.2026.01.21.08.22.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Jan 2026 08:22:55 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82d as permitted sender) client-ip=2607:f8b0:4864:20::82d;
Received: by mail-qt1-x82d.google.com with SMTP id d75a77b69052e-50299648ae9so523661cf.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Jan 2026 08:22:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769012575; cv=none;
        d=google.com; s=arc-20240605;
        b=iOiivV/8JAx4+xL8dONydqRDGsuNwELRFdfPa6x3Mi62Qgb5iXrvxfHaoUlwhrZTwh
         QKi9m1ge10ljerQBkVsnBCnJPFVXmAXs5b5/LZoly9ynFk23iUYxmCW5uTO0oZoCnfle
         JUVecEmaUi8EeegTP3NEm4IG5MEAxeNFAwuVIxtNxUlfEgW26V3SanT/5xtjdoUBgsI/
         WBCIHOsiKly23IRpAt0dklRMbIoSJh/njTjZd7HUsAJEmCxztVkFkpUMccBFaF5PmdNb
         R9vwuJCRH7YuwfnQ8y9Pb0nOqvAzzdZ/LZ2CdskEBFiG9c29kSunXQRMJ6NYQrz8z17z
         FNmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=zZKKP+4IZYFDaCDFilC88QfoYGNpM2dFv0WidsWIKI4=;
        fh=SmdH6JDaPvZaj0XLi4l1ENnA5W8xShS0wi8pvunvtWQ=;
        b=ePs8S409CS8G72J133wrnyz225yBHNCvMd6qK2m09Ss3AT6HxmNrSgnLIBK/kwyGHx
         KJ0/Y8lKcL6ntB+Ulx0Ho2VYTTe57JdYI7+Qo0sn0rTJeqoLxgjIPehqJQuCdacu7bL+
         97Wv8+Sl7pDKoabLRXhlJGUwNfWD1ObmrSDvvO4OIojkLeHvFVhHzUt+6CCmZ8cLnBqA
         DZiSmXfP7+TCLaN34vRndfc1bFX4It7x69l6LEN+qxKBWa742YjuzIgRhPD5DXBSf3fX
         /VbDMVPUnrKJ2gFm0MEiFB7TjcdtWP2oZANUc2mI4F3iD6lOK3KRPsUEPkby4aRuYkj2
         nLGw==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCUl9Za4vdBiCHwWTYOnPBeL7Yse7P7DbVhccAXN1a4ROVHxkH54z8SP70yzAAySWdEXltiqEi4qFRY=@googlegroups.com
X-Gm-Gg: AZuq6aJJ0QReHOjWM5jVBEBV/6moCCCqd6GDYXYy6zLYUBNiN2pH+2RprsWA+kNU1qq
	XHtKubHpwCi4Qj1sMy4J+RDlLXKMJz2fB+ATqC9LiSnCHy9iI7dzN/3aXSSloZDAUoXfVbMUrxo
	Fr2iqpLUavT3cXn20t1Iq7aP2M9GJEfIG/DsPOl9oGFM9Rq70o0YALqdLalG5zQGIKJHozklans
	cZXDCA7hMvTqv5VW6WJVtEFD9n09lFh8QNENyHsIFuz/0pBV53VR+jQhrALXxyuHBp+IRTuTBAh
	W378ASSou8euKNY0EAvko3g=
X-Received: by 2002:ac8:5f49:0:b0:501:197d:32af with SMTP id
 d75a77b69052e-502e0b52d5dmr15160751cf.0.1769012574328; Wed, 21 Jan 2026
 08:22:54 -0800 (PST)
MIME-Version: 1.0
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-11-5595cb000772@suse.cz> <CAJuCfpHaSg2O0vZhfAD+61i7Vq=T3OeQ=NXirXMd-2GCKRAgjg@mail.gmail.com>
 <c17d4413-1ffa-4d3e-8d87-0e7c2b022c16@suse.cz>
In-Reply-To: <c17d4413-1ffa-4d3e-8d87-0e7c2b022c16@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 21 Jan 2026 16:22:43 +0000
X-Gm-Features: AZwV_Qhsac_Z51cYOHKUSuzgrrT7X6Hd2cSKwh2Th8VEqlGKrAYEFKE43eae864
Message-ID: <CAJuCfpFUsSKf89tVe6u29SpN7sL1X_721H5iv2yGwt-Wa6E_xg@mail.gmail.com>
Subject: Re: [PATCH v3 11/21] slab: remove SLUB_CPU_PARTIAL
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
 header.i=@google.com header.s=20230601 header.b="nsAY/czb";       arc=pass
 (i=1);       spf=pass (google.com: domain of surenb@google.com designates
 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=surenb@google.com;
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
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC7OD3FKWUERBYH2YPFQMGQE4XGP4II];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail.gmail.com:mid,mail-ot1-x340.google.com:rdns,mail-ot1-x340.google.com:helo,suse.cz:email]
X-Rspamd-Queue-Id: 215E059D43
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Wed, Jan 21, 2026 at 2:22=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 1/20/26 23:25, Suren Baghdasaryan wrote:
> > On Fri, Jan 16, 2026 at 2:40=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz=
> wrote:
> >>
> >> We have removed the partial slab usage from allocation paths. Now remo=
ve
> >> the whole config option and associated code.
> >>
> >> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> >
> > I did?
>
> Hmm looks like you didn't. Wonder if I screwed up, or b4 did. Sorry about=
 that.

No worries.

>
> > Well, if so, I missed some remaining mentions about cpu partial caches:
> > - slub.c has several hits on "cpu partial" in the comments.
> > - there is one hit on "put_cpu_partial" in slub.c in the comments.
>
> Should be addressed later by [PATCH v3 18/21] slab: update overview
> comments. I'll grep the result if anything is missing.
>
> > Should we also update Documentation/ABI/testing/sysfs-kernel-slab to
> > say that from now on cpu_partial control always reads 0?
>
> Uh those weird files. Does anyone care? I'd do that separately as well...

I'm fine either way. Thanks!

>
> > Once addressed, please feel free to keep my Reviewed-by.
>
> Thanks!
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AJuCfpFUsSKf89tVe6u29SpN7sL1X_721H5iv2yGwt-Wa6E_xg%40mail.gmail.com.
