Return-Path: <kasan-dev+bncBD3JNNMDTMEBBPHBULCQMGQEHDQ2LOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id C80C7B321E3
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 20:02:37 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4b109be41a1sf95378021cf.2
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 11:02:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755885757; cv=pass;
        d=google.com; s=arc-20240605;
        b=GiojVV8g+My59xb9xnma2jMKGg3OK1XSj+wzwpaE14RzgM2bb37ES+W1Rowh7TLUDc
         IPU4TTsaJCQV1ACko25I3WXHfbWWb3DyOzRansObt4NasCj8yEGmBAx4wIXbgyhGpfTw
         Zryt9iceoGfQNoYs7oWKqqUYFa+rL5bca3mbJP2EZletfi97voHXImYDe8Yc38PCvgdB
         JQqUXZmX3Rs1F+BYq2uKCJLzsPZq9JFvMQI6EggaysHXh3bb1qSlE0H0WM2PUg4UIU0R
         9eocyfKr4ZgooRc+pPsPB1SXc+qgc93V9Aa6/XmKcQEbPmRntdaW5G/Mrh38PlM4/Okw
         r6bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=NlwkzJ9kJlOEpDarfHwHynvzox1OvjLcvxJxjBAh6CU=;
        fh=+3IRzum4VL574p+H0idOO3ldNnzOgy0C4wP2rt9l4fw=;
        b=cbngvSXUdYtbuZEP3xzfJGE1KkVPTLa4ISjK9TTWKpJLijEs2YrfSluzBh7/Pv8/2Y
         J+PT6wypWVo8B8GsPjQ/z8fqizeYCnpBx46aOoyQeRxDP7EsckhnpqHt5B5N+ra54HaC
         oA0+Amv3BLnfPy13+Ca1xZVnPm3eslIr4OauxJHqNoI7cL5Y5uyZlI15G6b1D4Red0//
         nKM4CzZsNghMhqQ6CjPgvye/uHNUyTlEr1R8DdKNtkFnLS/GAOX7CazGNnoYkkB2AbKQ
         2trLy5kBHUYaNMF8F1+n0VXeThOUnSHzq7yTXdI1JaADa/XaL3hkVv2QoIexibKNt5my
         Y+Aw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=jIHiaXUZ;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.3.7 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755885756; x=1756490556; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NlwkzJ9kJlOEpDarfHwHynvzox1OvjLcvxJxjBAh6CU=;
        b=E2dwwOmEOhuW7RLwGOGeVX9YHbgtOxouKaWzcEIr1shtm1dVBX49Q0+3ry//+QB+NC
         PjeshlySn9VRTd1tec2R4Paq89fldiO3KhvlZVD9DrDsY0OGQHfA+hpCNT5AUkg9lBpv
         09HSMj5sYeXaU2Q3kIjs8s/iluYiyj+QMyAKm5qheaEHOyFmJaazjgXsB/0tNy/LzUDF
         LKkkbB4tgGnIfjJlsKQhz+RfnV637YV1z2cUODP18nE7CNVRSvd83g7Estrovs3cEcF5
         cDoQqL2V5lK5lbOwjVzZXp2GIDw/nPZQ153zZjiWRmKQEOAfVX0i8pW4zyhVb4Ch01c7
         I8qg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755885757; x=1756490557;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=NlwkzJ9kJlOEpDarfHwHynvzox1OvjLcvxJxjBAh6CU=;
        b=aUvC8hgGnMLE1JMCzkn4vsSTvCM0i7gLWYlLGRJwDxrLD8WWPclWb3IBaZkewVwesw
         Ci6167pBz//xHATyzOaYf074wRg5+qYnK+xio2U1TrmIy+UXog3+H/NOEqRQX7Dx5WeB
         JrubNaX1hzuagZ2yncO4VCXp1VzV3Q17PZ7GLlLCI97TbQbhvISHbo7N3vNeLB6VOVQS
         XgywPdFk50Zexf6tSFtj2PZ3kQ3iVoa3/7Xg4QSHXGZ1+O+XUkzgpy6v2G97mZfD6PK3
         o9+APGcWPr6wvJt9aAdFFMUb2HJbLR4bBOKQIllgtPXd2gf+i0in+sKrqtJvhmJkz3Te
         0MrA==
X-Forwarded-Encrypted: i=2; AJvYcCX7kqF5BoZUFiziOPiLfLgZ2O45WDQDt3yrGEW+ZLFS8Js9s05qAd99N9wIxKTu0RlLDJScDA==@lfdr.de
X-Gm-Message-State: AOJu0Yy/AANHpnzLQaLrlFZGKzMR4kaXkmkW0uiKst2FoIfODCpoDTPa
	phJylwrb2e272j3Zsloc/PhhbwdVt3cL6WDJBGQH0MvpIPdPRWbJJMCb
X-Google-Smtp-Source: AGHT+IGi009XZRhNZxN/eqdq2cRK4Z5ATUEWN0cAyNvwUQPaN73WivBeqjk82HikraKCi8QGJNmcuQ==
X-Received: by 2002:ac8:5f0f:0:b0:4b2:998c:c488 with SMTP id d75a77b69052e-4b2aab0d443mr38062921cf.54.1755885756685;
        Fri, 22 Aug 2025 11:02:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcdl219nFwRw705bYxLLmoI3Vi9ajGtFBX2gd2tasRUig==
Received: by 2002:a05:622a:1789:b0:4b2:9b6b:2e97 with SMTP id
 d75a77b69052e-4b29d7bcb9els39506481cf.0.-pod-prod-04-us; Fri, 22 Aug 2025
 11:02:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWPSbz/yCbQMO7F95EXOJqZFb0m9LOi3W3td0aGE5FtCgU1wqord42TLD/ADW82E95Fb3CgyIh+HKI=@googlegroups.com
X-Received: by 2002:a05:620a:c4e:b0:7e8:3fbd:4190 with SMTP id af79cd13be357-7ea10f94e80mr512072785a.2.1755885755611;
        Fri, 22 Aug 2025 11:02:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755885755; cv=none;
        d=google.com; s=arc-20240605;
        b=Y8CNnPGitpf06/kYJtl2EjHxtXIvBxuD98h6nQF1v+MpKvN8lxG+5gu1FepBSD4rHh
         HZDBmH5CQV9FC+oSLhozypjZneC21GewEkBuskQX1nwZsGs3Ewce+JTCU4PG6uetegre
         V9DEWT6IJ62GvdSM8vfaw0XWuCqGYcdRFfP9Pt06eEFWmDMwI2LAHu3EIfrY8g29Zv/l
         hn1cMPGAYacj6AOZFymaQUoDApaxEcSalEF+jsn/RwOIwPkNKcC2xIZUKyUKJUWEDnCw
         tpWcQ0GUqTFYciCMItaPFdtRT1HgVwhL0K+DUiNTxN0E3poe6DvoU6Hs608mhQm4YS0k
         TPqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=lOWWilxxOW7+2VFeqILToF3FfKlMIiqdFUMj7Kr1eMs=;
        fh=qZClpRkdJzwoo4mA2CFPJds6rAkKXHHsvko9BIR3eeQ=;
        b=WfsUg6rO4Bt7km1MXi6myZEV0yuQxUWRpSyx3tmVzKo7mdQag+uNUTUfsGKFsZo0F9
         ggOedIqK0mrooRUdNpiEi+XLRT8CSiFPSSPyGh/3yQuMkvtz0129brEz/J4MHYtL0kzk
         hkOv74Sb3B7/2QRSMALj8uxhR7O+NhmNWSNJ4m2gUlAqctQLpydPd4vtkcHZMUQAtLW5
         xIfordI+ZTTNPjz0rHPYSoX9oWWdJqsuvM8vIIyqgyQI/Ls6SfjTOgSo0ZZ5lF6EWeD0
         22gK6U21My7bR3yIrFAWmRFaoabM4L+JNUJjuc/E5P/dxn9ty3EtWsiluikUJ6+8lLNO
         0h5w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=jIHiaXUZ;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.3.7 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
Received: from 004.mia.mailroute.net (004.mia.mailroute.net. [199.89.3.7])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7ebec276e66si1623285a.2.2025.08.22.11.02.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Aug 2025 11:02:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.3.7 as permitted sender) client-ip=199.89.3.7;
Received: from localhost (localhost [127.0.0.1])
	by 004.mia.mailroute.net (Postfix) with ESMTP id 4c7p1l0sq5zm0jvk;
	Fri, 22 Aug 2025 18:02:35 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 004.mia.mailroute.net ([127.0.0.1])
 by localhost (004.mia [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id TWskR_z3NWFT; Fri, 22 Aug 2025 18:02:27 +0000 (UTC)
Received: from [100.66.154.22] (unknown [104.135.204.82])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 004.mia.mailroute.net (Postfix) with ESMTPSA id 4c7p0l0k1mzm1756;
	Fri, 22 Aug 2025 18:01:41 +0000 (UTC)
Message-ID: <58816f2c-d4a7-4ec0-a48e-66a876ea1168@acm.org>
Date: Fri, 22 Aug 2025 11:01:40 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 29/35] scsi: core: drop nth_page() usage within SG
 entry
To: David Hildenbrand <david@redhat.com>, linux-kernel@vger.kernel.org
Cc: "James E.J. Bottomley" <James.Bottomley@HansenPartnership.com>,
 "Martin K. Petersen" <martin.petersen@oracle.com>,
 Doug Gilbert <dgilbert@interlog.com>, Alexander Potapenko
 <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>,
 Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>,
 Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org,
 Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>,
 Johannes Weiner <hannes@cmpxchg.org>, John Hubbard <jhubbard@nvidia.com>,
 kasan-dev@googlegroups.com, kvm@vger.kernel.org,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, linux-arm-kernel@axis.com,
 linux-arm-kernel@lists.infradead.org, linux-crypto@vger.kernel.org,
 linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-scsi@vger.kernel.org, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Marco Elver <elver@google.com>, Marek Szyprowski <m.szyprowski@samsung.com>,
 Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
 Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
 Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
 Robin Murphy <robin.murphy@arm.com>, Suren Baghdasaryan <surenb@google.com>,
 Tejun Heo <tj@kernel.org>, virtualization@lists.linux.dev,
 Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org,
 Zi Yan <ziy@nvidia.com>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-30-david@redhat.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20250821200701.1329277-30-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=jIHiaXUZ;       spf=pass
 (google.com: domain of bvanassche@acm.org designates 199.89.3.7 as permitted
 sender) smtp.mailfrom=bvanassche@acm.org;       dmarc=pass (p=REJECT
 sp=QUARANTINE dis=NONE) header.from=acm.org
X-Original-From: Bart Van Assche <bvanassche@acm.org>
Reply-To: Bart Van Assche <bvanassche@acm.org>
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

On 8/21/25 1:06 PM, David Hildenbrand wrote:
> It's no longer required to use nth_page() when iterating pages within a
> single SG entry, so let's drop the nth_page() usage.
Usually the SCSI core and the SG I/O driver are updated separately.
Anyway:

Reviewed-by: Bart Van Assche <bvanassche@acm.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/58816f2c-d4a7-4ec0-a48e-66a876ea1168%40acm.org.
