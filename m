Return-Path: <kasan-dev+bncBCCMH5WKTMGRB54OSTFQMGQER2DPEWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F752D1334A
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 15:38:49 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-4ffb40c0272sf155233681cf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 06:38:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768228728; cv=pass;
        d=google.com; s=arc-20240605;
        b=QaWazh8p3dnPycimIkY3rQe5I+7bk7Jx4vCI9ER8m6ImeQPCO2gM9Tgau9Ns1GAlLq
         KXp/ZBnKT+gFkwalH4mlWHpUsv8cm8TWqni+CZX4rgCVDliiClJ3ZlTEVuEbhPIM2oB6
         OmBu4MY6eFlmzAYxVV1fwtdVI0YGyrB3GZkdmIcwHMD8DAzsXSeOFKiYscHmyg2VXNfo
         OHElPFV7mSEwgepFJmTehRjdgBQN9QHvbr+Ez138HpVH0CIas53b5wjU57oZkGtyZhhk
         +D6/f9IbD0BjyjFDfQtMdLs9VI2AxcwCWsCq7YYVFo3YrLLkVmyk1+gqtWpI2xq3vZFo
         pP1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MFmU1YgmWMV3yyKqzNrPP1UnRbgBRuPc15aAG9dvyII=;
        fh=rGSsekX+BD/V+o+TU8Z131MOvtBI/6Utf6SBwp/hAuE=;
        b=TfhBDewZmVkU8bpu8F7p1hv0KrL9EqBnuSmxKiy6T04du/I9g8YBFRRqxPqfdk+Q6S
         UPyAjiMym+5xLPmsqAA1PC6QxiFVqUFwPieaAhMatYWXChZAOLUEcLTIMYmiQyN8MnOA
         VtcGZabOqDGBnJzVhkoRACzKEnIgFJzI808lrrvpbnqs8MSVL/vHGXFFMjvhKqLjMNnl
         7pnU+25Wg9tKkOwkdH7I16/rckLknc+5PvvRrDPSc+CaXPFrt9f0bU1T0ricItRKssu6
         sLwZGBpBnkXJzz86nzxgVq7+IryXGtNjqZu9QzLAs4yy7F/3LSNX5jAZaQ92lZT2YXZv
         Lj3g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KmskbwKr;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768228728; x=1768833528; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MFmU1YgmWMV3yyKqzNrPP1UnRbgBRuPc15aAG9dvyII=;
        b=i/evcurrQUs+9/M7YOazog8Mll+vCRdASGJbpBkw2z3UDb/elniZOYvK2dh/HyJDrV
         kVa1D18cWp+T/YQYrIFtKyRNVo68IZyHs+UKjN1/2n60ASDLV6dSd+429wxjuvCRkRze
         T6/TQW9iVHEiyFz9fCqAl23GVjscYeUGsgAyEzCQTkNkDGJoLOi+FDnL1KFa8Kr4WnuV
         K0hUm8fpqP+4t8SRpwzJUMeAegaMWkHsvLUIm+QtNKK40sWzi5rYLVojfXCQo0slUXwk
         OCKH9lIyT4IBbcuvDmFqdQhbcf4hfKecyhyckTFO7i2vqSErgMIRIlbGRejCJDNP804X
         JA9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768228728; x=1768833528;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=MFmU1YgmWMV3yyKqzNrPP1UnRbgBRuPc15aAG9dvyII=;
        b=IG6lprPZLIqVJGjoFpdSSEQ75OIiqkmj1ZYl7U35zTMvg3U66syibw1yq1JjDaVmBB
         d/nhUw27APEgf7wPEDvK3ybE99pE1ZsUJ5jE+rG8EsEa64ZZ+tEivRPjqxOZxnhcDCjf
         Z77Mwlmd9POnECro8Mmy+UVtGe7VpWiTHuWFi7AsIJHokgGDNe2fqF123zF+ph8c/ZQp
         98HGF7urieYEweGLuPDAGISPSH+e3pl6bFJWAtCLRXKEK9WwNwYiYQD7Y7Rxi4zDvTik
         XCL2ot2AWOIEB5VldAMPJr0XV7o/Dik3kf8SD9mJtsCPhHAVCS+extxsKR5SiiPh4Vsp
         LYAA==
X-Forwarded-Encrypted: i=2; AJvYcCU3+De9X2wwGx5ZoQbmBrPrhZdpGLnZEiYg3iLXp3LmMV+YHqWd/ElMczkyNLxd7pvs1xbW1w==@lfdr.de
X-Gm-Message-State: AOJu0Yzv03DaGdjhKlxLQSTYboCT2PaFdYWKXGXp8LG/h/SaHAOi5sxP
	51WOZ14sJbcsxTVNzo8M928lXbSZlCOzJW9DeWzFtxkpR52LdWpX0wfP
X-Google-Smtp-Source: AGHT+IHqvogSHWSPnN+/6xJdfBCJEx2h6h+ygkhVtBtL1O1CTz+EOpb2AX5FyoaB97IFbFn2HWJQpg==
X-Received: by 2002:a05:622a:9:b0:501:19e0:cd2e with SMTP id d75a77b69052e-50119e0cdc5mr104769321cf.38.1768228727906;
        Mon, 12 Jan 2026 06:38:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FHQq452vn2OHxuJaqyhOT+Ghkl3IZJFoSWzvdEHAYreA=="
Received: by 2002:ac8:580f:0:b0:4ed:9424:fa31 with SMTP id d75a77b69052e-4ffa72630dels139650001cf.2.-pod-prod-01-us;
 Mon, 12 Jan 2026 06:38:47 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUSNyobXrkmKPI+Bts299UgaaKobSB3TmkR2Cvnb2OZkUWYaWpg70qxK0hGxqaNqMsXSl7Ah3pHBB4=@googlegroups.com
X-Received: by 2002:ac8:7d47:0:b0:4ed:67bc:50de with SMTP id d75a77b69052e-4ffb4958b63mr276992851cf.24.1768228726855;
        Mon, 12 Jan 2026 06:38:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768228726; cv=none;
        d=google.com; s=arc-20240605;
        b=TuOWfG6KFGgkQQGRKKVo/V79rb0LuenllCCZzkV7H9Od/J3heMiGqLvfu83zDGyCCK
         Rp6Rok4ULrBePpQxPN4/vIhVoo+RGDYQvdbb0tB28MELpFX3jZS7+BkGiFSz0UqnpEqi
         t5v49CPSX9CYGg1uKBVJrUgPY69L5EKTeZTj77lWsW/QM7z2DaBCxKkMBQnspeyDL0UE
         jcyPVihfs3ukWz3ZckNFHsOYHbH4EYi8NBWiwWeN0Zh6DM9Q1AloI7N3tVLFiw/wJ1PE
         b1gJtd6+nG1R6UdyXX0NXjPiBuR+EUg6uOlb6MVKOAqk0Yr6lkaC+Y3PJYBXLKn1+1ZR
         QoTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=3OVHLwGSVY3ROBM8cymA1lSVZ22bXnEcQvZKsbH0Omk=;
        fh=UIh4wOpzpgkk+eermUHb+3YWNTVhYy+mVdEP3mi1GOs=;
        b=RVGljJ/RliXOoMvE1YaaRcPalZH0P0w63UQsKee+oBwAdgn7+7XAvtwjq9L8mTDy0h
         ljeBiEcPkiakJaRMAK3icbcP9moMxkBgTHbml7hS44x97eAvP/EQgQOdbaNVnt+y/dkE
         8cpE3EAd6WjAvIy2UwSYY/CFyv/ZFl9yGlPOXMm2nVlqefzLWt4dhzqgjBDHVwuiIERH
         OQbgli+UUGwjgL99vSYYxUvBHz3okckgTsjQOPfADFw2d7wc7TXMj1PBF5zHdjIXVjhM
         r/zjrHWzz1Kiun2KvTjry4IODsdZ6Mx5iFfDLyjUDHE8XS09aaGN91hJPTxJ/EyAVjNR
         nocg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KmskbwKr;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x733.google.com (mail-qk1-x733.google.com. [2607:f8b0:4864:20::733])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4ffc4f10730si3795571cf.2.2026.01.12.06.38.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Jan 2026 06:38:46 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::733 as permitted sender) client-ip=2607:f8b0:4864:20::733;
Received: by mail-qk1-x733.google.com with SMTP id af79cd13be357-8b2d56eaaceso740171985a.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Jan 2026 06:38:46 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWcs/UJIjdUkro05JH4CaysnMPOiPiSWRTfY2tCHhVON3IStXWxhRIdM7ezi7Bc3AXtwBXCRD01ztU=@googlegroups.com
X-Gm-Gg: AY/fxX66mpJvebrK9zj7/VBY9WRHnQE8g+wmE7PKSk8JHIJ1KvbLfVSfsqmuGEpOQ4H
	elZSD+Ud+lu21ekVcd414jRKTfrEeB8s+m0sop55eAP3Mmv7TlokCDOUctBgCxapKdn4HDnjnCD
	Gc7NE8WlK4GLNBqoJteiEKNMy4YRykg011R/pbsDtpIg5LI+5xZZyMlzT9OR/5Tigpa/gZZqlBN
	hQpufRbdrDQNSETYJz/jWUBb1pFt1xYq53tKte/JoxmSjopdhNYd3dtIpvQT0T7nDY7Blbv4aPt
	F/bpbkw76jmF4ZzWS0Xvqkbp4w==
X-Received: by 2002:a05:620a:40d4:b0:8c0:f13e:42ee with SMTP id
 af79cd13be357-8c389420351mr2515603785a.88.1768228726114; Mon, 12 Jan 2026
 06:38:46 -0800 (PST)
MIME-Version: 1.0
References: <20260104134348.3544298-1-ryan.roberts@arm.com> <20260104100230.09abd1beaca2123d174022b2@linux-foundation.org>
In-Reply-To: <20260104100230.09abd1beaca2123d174022b2@linux-foundation.org>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 12 Jan 2026 15:38:09 +0100
X-Gm-Features: AZwV_QiYkGu98o69ZXegThGdFPJzrbQ3TdfnesIl4fIhpP9VWTIXvd7AfjMrgqQ
Message-ID: <CAG_fn=XtONeeJzBFFyxqWa1=Zo8bCGcUPO11Kaa4093vJOPgrA@mail.gmail.com>
Subject: Re: [PATCH v1] mm: kmsan: Fix poisoning of high-order non-compound pages
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Ryan Roberts <ryan.roberts@arm.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=KmskbwKr;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::733 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Sun, Jan 4, 2026 at 7:02=E2=80=AFPM Andrew Morton <akpm@linux-foundation=
.org> wrote:
>
> On Sun,  4 Jan 2026 13:43:47 +0000 Ryan Roberts <ryan.roberts@arm.com> wr=
ote:
>
> > kmsan_free_page() is called by the page allocator's free_pages_prepare(=
)
> > during page freeing. It's job is to poison all the memory covered by th=
e
> > page. It can be called with an order-0 page, a compound high-order page
> > or a non-compound high-order page. But page_size() only works for
> > order-0 and compound pages. For a non-compound high-order page it will
> > incorrectly return PAGE_SIZE.
> >
> > The implication is that the tail pages of a high-order non-compound pag=
e
> > do not get poisoned at free, so any invalid access while they are free
> > could go unnoticed. It looks like the pages will be poisoned again at
> > allocaiton time, so that would bookend the window.
> >
> > Fix this by using the order parameter to calculate the size.
> >
> > Fixes: b073d7f8aee4 ("mm: kmsan: maintain KMSAN metadata for page opera=
tions")
> > Cc: stable@vger.kernel.org
> > Signed-off-by: Ryan Roberts <ryan.roberts@arm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Tested-by: Alexander Potapenko <glider@google.com>

Thanks!
I'll send out a follow-up patch with a test for this behavior.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DXtONeeJzBFFyxqWa1%3DZo8bCGcUPO11Kaa4093vJOPgrA%40mail.gmail.com.
