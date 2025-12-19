Return-Path: <kasan-dev+bncBAABBN5MSPFAMGQET3DFRRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id DC176CCE74D
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 05:36:08 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4ed82af96fasf28233421cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 20:36:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766118967; cv=pass;
        d=google.com; s=arc-20240605;
        b=IKcXsOBI3/Yx6KoykqANets0doCWRsDQA4/8VcqLnQJKUj9SITG/ZR7yKcHufqkuF8
         pvC3+63YOpT9WsU62pMVhZV6x14gOTN4RQyV3CzMdno9nXRuIOav6mnSu+dJKcqcpWYg
         nIyzlHyCl3p4LLG47q1Cc0Ui2HmL4O1uF8zx95fGkP0UfnMZBYVFtKyN38OEwjO377re
         r+lXcczbHG1mTc4iLVxAjcZO0jYM/+niHAi5ZkTKyvOgYlEO7lK5qMgJzf79RcKBg1FF
         mupX9+akpc4RUKO5CzK7JlzAoVVjGe0g8amI8sKOkVy6U8ZAPNLDfitlIQi3lSvmSds3
         FBRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=PhxIp7RU46y3C3NbpD10OuEXAQJ82LsHQGoEi/IzY7c=;
        fh=hlPrj2AzJraMCT6L1QBp8jjh3Fq1RsoLjSGkGpCP7MI=;
        b=HNjTdG44315dUmhDw+bZL0tHS2qX8CS2uXuhFlTtQPUJN0JUl7Lcyvn9a+IUjc1M/z
         637Lw0wBjPBE92mNRGi+6EGl1SF4GekRBQ1p1f0aUGiKtTHT91jbDUoOIeUBJdfOEa3Z
         rXjUr0u9NmBPE1p2bUMVSDmBdalK2RqPThBzb/tKqSYtDeaLg5FwoPGvNTIWFne+Xkqr
         8mf9Ios/MmIp88vLf3yfRhMa/1f+B7Oxi2KpSM8Iu0t+NlcjMvQhBBOGSnwa6rdO0xvY
         NRoV1PvLwT5pui3AXj375VM2ttrZpCtnDlLosGwtE8JZuVa8ssrzZOSyHSfwBTiVYEVy
         ZIdw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yuanlinyu@honor.com designates 81.70.206.69 as permitted sender) smtp.mailfrom=yuanlinyu@honor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=honor.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766118967; x=1766723767; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PhxIp7RU46y3C3NbpD10OuEXAQJ82LsHQGoEi/IzY7c=;
        b=YI5Kn2vY3+DLtHcUkdn+kbzI5qFldRHb4DhFWWZ+53PYLzr8ae7lY7xjWr+ZvNNn9M
         F3BQ/rqPlwCAEeN8WX/TJQXJQ/H5K23W9uWP4tP/zSQk2QmPaFG0d9zZMUhll+PwEjj5
         liIXlg2eoRi+N66qgwFTv992Uz8rnMblheP2u981I3Fn25N8/KwMrRS36G2b3qUsruox
         s9SA6ofvOn/+o158mev3ss3QGiNJpcr2TDVjipOfdSNMmrxIlImHM8Eht8NCdJr+7w7U
         Yvx41P1PQOFFI1OFqhTNQ6suu6ZHWz8VYsEI/4u/Box81uSOMHBbFyVlfoG4Ams17yop
         g64g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766118967; x=1766723767;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PhxIp7RU46y3C3NbpD10OuEXAQJ82LsHQGoEi/IzY7c=;
        b=vKX9z5w02eP4bGoANQh9sT7JY1OGjp+9Z4xhhjje2tPv0RZPEqHg/QEZbxrrZRTe6j
         5Ek2DQTtGMydnTZ5m8Umiiq59hgYt0LZAKNfBjZyh0nsex+n8fqfjyj7mmu8e02T5a/v
         ytoMkKXgVSHvapSS4q6wNl5Tp5UbA7TzfKtWZDQ0jpeVqHQkGKvXOEov06Dz6vkz9ZiH
         hNglUz7Q+bCkEZ5CltLLGBUxYVuJRJ6U/NLvAwfGLnFih8oNREamNBp3fZuKukFwacaT
         +akBjXw8ee77iDiSEOE9UoaaQLzvLgXppBcJ6EmgYtHJ9+hZY5ro7r/c/AxIMGjRcM9m
         Nszw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVuMedthOJsBLN0wSb/jbKfHvS0cIbjp7O+OgH7kXD9UpePT2BO/pvKSLrOotAaZnJydaeSdw==@lfdr.de
X-Gm-Message-State: AOJu0YxEzfrYdESwImn2O/SKYMtFJZODg8ylWvxnGa9XyJbt+uKALvJI
	hgRS0uBRsH5SsLNsB4AlpvKEcYylgTdcCYjCUb+DmI1p0ipvD6b8JCfU
X-Google-Smtp-Source: AGHT+IHBmkl1/zfHtmy7MZRYjXpDqGDxpQOL28xxryJkR0TfmcN25g6303uR6Wno1ja3O/n766PduA==
X-Received: by 2002:ac8:5c81:0:b0:4ed:44a7:cf78 with SMTP id d75a77b69052e-4f4abcfc08cmr22976151cf.34.1766118967537;
        Thu, 18 Dec 2025 20:36:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaOijUmdtuCR6Eh9EM52PQABCxuoryQg8pywztP35h29Q=="
Received: by 2002:ac8:5a4c:0:b0:4ed:7bbf:d2b with SMTP id d75a77b69052e-4f1ced48833ls90728711cf.1.-pod-prod-04-us;
 Thu, 18 Dec 2025 20:36:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVCez6nhLxKKOs2IAIjLE2V/qKHgl00ldWrurPudq7KS7oTB0CsnRDvds/rRqZtpCkc3/wWCKkjr3U=@googlegroups.com
X-Received: by 2002:a05:6122:1d91:b0:55b:305b:4e27 with SMTP id 71dfb90a1353d-5615bef2335mr729068e0c.19.1766118966710;
        Thu, 18 Dec 2025 20:36:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766118966; cv=none;
        d=google.com; s=arc-20240605;
        b=GhYxm2c3TyDlV8sPMAgc4kKoUrRITdQG9CPt8MzCVGP69NfdF5EeiKSdJw7Lh+60yg
         ItE/8J7EgQJ896H/73sUYgzVcAnjsiLR9cTuwOLVLpLGEKJ2GeDxkKNTO1/M+DuyET1Q
         B8stAVm1iiHn01bozx7vwWA6TyU0zu73ZJhp26kWnZAfFp7XDjqKGrOSi5ZZHIaw/oR6
         LRHDI4X+3m5/xiSt6VAbx9APz+uOxNOTQ8ObvZFbXV7kgpGvftbBBD83U/1lUg7cYowo
         /Wc3rqwdFCevFRM/dm680e8m3FPtmj5BiNldIohSfNzi3Fea6XgRDMJmv7jXxM2/5GBA
         CFWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=TBeoBMXlMEVhwhMkEcXIUeqtkasMEWs5iVpIxMFXugQ=;
        fh=sRLLPD1NR0EEBTnxwxNZlNZHRxniOboIlZTQ47sl21w=;
        b=BI2SB5DdsRuqE+fQzW7zO4cNWwQjqzgKGYkDBOro72NCRakRUdYMTLl2J62x+yl7eH
         HtXC2jZsyMNvqvA7zzDRWwJ9fEVWYpz86L1J5SY1fCLXWXO+IkUNZ9dCtqsZWQY980qF
         20fkIX/ymNaVB5Gbxmkn7h2gIeKoxxMapHASdCmXoTF0Vuo4F/dZEOy+6T1jnLQUAhbr
         71BrXcjPXVID46xc2LtXHFcvfqcJw2yZecIfpkIkXGzqoH++EtB6Btsajnm0/nUgrGVZ
         WZGeYCslWqHxYzzxrQMzDwXxGSSEYpw9CkMhSFTmi/BiwYeM4dukKNcI3b0dsd7QxVku
         xscg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yuanlinyu@honor.com designates 81.70.206.69 as permitted sender) smtp.mailfrom=yuanlinyu@honor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=honor.com
Received: from mta20.hihonor.com (mta20.hihonor.com. [81.70.206.69])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5615f761dc8si11833e0c.0.2025.12.18.20.36.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 18 Dec 2025 20:36:06 -0800 (PST)
Received-SPF: pass (google.com: domain of yuanlinyu@honor.com designates 81.70.206.69 as permitted sender) client-ip=81.70.206.69;
Received: from w012.hihonor.com (unknown [10.68.27.189])
	by mta20.hihonor.com (SkyGuard) with ESMTPS id 4dXZRC3cNKzYlLgM;
	Fri, 19 Dec 2025 12:33:27 +0800 (CST)
Received: from w022.hihonor.com (10.68.16.247) by w012.hihonor.com
 (10.68.27.189) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.2562.27; Fri, 19 Dec
 2025 12:36:01 +0800
Received: from w025.hihonor.com (10.68.28.69) by w022.hihonor.com
 (10.68.16.247) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.2562.27; Fri, 19 Dec
 2025 12:36:01 +0800
Received: from w025.hihonor.com ([fe80::5a3b:9b85:bbde:73b9]) by
 w025.hihonor.com ([fe80::5a3b:9b85:bbde:73b9%14]) with mapi id
 15.02.2562.027; Fri, 19 Dec 2025 12:36:01 +0800
From: yuanlinyu <yuanlinyu@honor.com>
To: Marco Elver <elver@google.com>
CC: Alexander Potapenko <glider@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, Huacai Chen
	<chenhuacai@kernel.org>, WANG Xuerui <kernel@xen0n.name>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "loongarch@lists.linux.dev"
	<loongarch@lists.linux.dev>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>
Subject: RE: [PATCH v2 2/2] kfence: allow change number of object by early
 parameter
Thread-Topic: [PATCH v2 2/2] kfence: allow change number of object by early
 parameter
Thread-Index: AQHcb+kJOevioCwokUWRSuHGy2xym7UmkpaAgACVZ/D//4LNgIABtVUA
Date: Fri, 19 Dec 2025 04:36:01 +0000
Message-ID: <a5937489d22f450eaecca610d8aef6c9@honor.com>
References: <20251218063916.1433615-1-yuanlinyu@honor.com>
 <20251218063916.1433615-3-yuanlinyu@honor.com>
 <aUPB18Xeh1BhF9GS@elver.google.com>
 <7334df3287534327a3e4a09c5c8d9432@honor.com>
 <CANpmjNMmiXjifpc9LdCVi5jzzKU3sgb0iJn7P7TMFMNqDH7TbA@mail.gmail.com>
In-Reply-To: <CANpmjNMmiXjifpc9LdCVi5jzzKU3sgb0iJn7P7TMFMNqDH7TbA@mail.gmail.com>
Accept-Language: zh-CN, en-US
Content-Language: zh-CN
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-originating-ip: [10.165.1.160]
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-Original-Sender: yuanlinyu@honor.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yuanlinyu@honor.com designates 81.70.206.69 as
 permitted sender) smtp.mailfrom=yuanlinyu@honor.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=honor.com
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

> From: Marco Elver <elver@google.com>
> Sent: Thursday, December 18, 2025 6:24 PM
> To: yuanlinyu <yuanlinyu@honor.com>
> Cc: Alexander Potapenko <glider@google.com>; Dmitry Vyukov
> <dvyukov@google.com>; Andrew Morton <akpm@linux-foundation.org>;
> Huacai Chen <chenhuacai@kernel.org>; WANG Xuerui <kernel@xen0n.name>;
> kasan-dev@googlegroups.com; linux-mm@kvack.org; loongarch@lists.linux.dev;
> linux-kernel@vger.kernel.org
> Subject: Re: [PATCH v2 2/2] kfence: allow change number of object by early
> parameter
> 
> On Thu, 18 Dec 2025 at 11:18, yuanlinyu <yuanlinyu@honor.com> wrote:
> >
> > > From: Marco Elver <elver@google.com>
> > Do you mean performance critical by access global data ?
> > It already access __kfence_pool global data.
> > Add one more global data acceptable here ?
> >
> > Other place may access global data indeed ?
> 
> is_kfence_address() is used in the slub fast path, and another load is
> one more instruction in the fast path. We have avoided this thus far
> for this reason.
> 
> > I don't know if all linux release like ubuntu enable kfence or not.
> > I only know it turn on default on android device.
> 
> This is irrelevant.
> 
> > > While I think the change itself would be useful to have eventually, a
> > > better design might be needed. It's unclear to me what the perf impact
> >
> > Could you share the better design idea ?
> 
> Hot-patchable constants, similar to static branches/jump labels. This
> had been discussed in the past (can't find the link now), but it's not
> trivial to implement unfortunately.

is it possible add tag to kfence address and only check address itself ?

> 
> An option that would enable/disable the command-line changeable number
> of objects, i.e one version that avoids the load in the fast path and
> one version that enables all the bits that you added here. But I'd
> rather avoid this if possible.

Yes, it should avoid, the purpose is without compile the kernel.

> 
> As such, please do benchmark and analyze the generated code in the
> allocator fast path (you should see a load to the new global you
> added). llvm-mca [1] might help you with analysis.
> 
> [1] https://llvm.org/docs/CommandGuide/llvm-mca.html

Thanks, will learn it

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a5937489d22f450eaecca610d8aef6c9%40honor.com.
