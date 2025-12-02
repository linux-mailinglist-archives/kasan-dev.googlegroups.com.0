Return-Path: <kasan-dev+bncBCKPFB7SXUERBA6MXPEQMGQEE6DCQGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 0140FC9B8F1
	for <lists+kasan-dev@lfdr.de>; Tue, 02 Dec 2025 14:13:43 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-4ed6e701d26sf99876831cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Dec 2025 05:13:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764681221; cv=pass;
        d=google.com; s=arc-20240605;
        b=ISb4bxERvK18g1xi0fY6MFYXA4rChNRUJp0iBL8wTgy9PrZXU+akRVd2v7gul/1b8d
         6oh/7EKZbDEZwOqDvVHCQ443w0BFZYpU96WxmqsWgxznokaAUZpd3wN4UMpXmIPlxWLS
         VnPF/cKGR5/PsNqlHtLbxPbB3na2iwm+uAbCQBakfTLsvE+f889HODQfYbHj1FG1TxlS
         BJoHQ/yeJB2B5jaR/9V7MOF2wRefb7jBk5QbKD89Ks8fqmaObH8hFffkqzKNM9mt8pPn
         JNd0u9zyJcq1Jx/PlqU4akLITO59rvWkENKNe/R3hnT2yelb7NQbHAahSe2qWlCzE6R9
         Y0RQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=K+4Bl/iHERcDPFKmyTAcsjAsPqCy8YVLMw2Vc1WCcPY=;
        fh=/hrfMVZKuZzEIerfiWCd+CgQm0mPWNxrC1m2kh2C6cM=;
        b=kEJGMJRvQRnnG7BAqmKngiv+mCrveHRUOz97pbR8cjqdy1GHrlE3kgjDmbvIc91Lve
         BeGRTQxzkSt+peeSaI/02PemTuEiGbpug7GYY+u2NYOwh2V3n8fSq6FOb/FsgZtEGef9
         qIjmq6j24q4t/5eHCnoQ4D1yCod3UeSGFGLf1dDSd2zIDVxnAeIBbgkVeZ/XNSfkYDpB
         aAF1lNk15LnNcL5tm3HwtJNV8ouykpm7dOzkoe+9OTlm9sxkOzjP/W42JJ80NEHU76Fx
         Nv4EY0EiBzzu9ERynXa4onNlpCzfn6HwaS+qiL+DzqJcrrn1DkDT4q8GIUPCMr+HDkZh
         J2qQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="E6NDEt/W";
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764681221; x=1765286021; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=K+4Bl/iHERcDPFKmyTAcsjAsPqCy8YVLMw2Vc1WCcPY=;
        b=wFwKWIApWrdx9x9HRcqQrvqyHJZlANICSkL3sQ2gPrwU76SZP/2JtkCgZCLO+333xw
         Vun3HpVbufckZCLhHhTl+JFEtfkFa/q/0bYa9GBNnO89wTm27fqrZaxSMDe6af2hgpyW
         byI5GRU5D2BucKziZakxfRqTQ6A9ScAf75ePJsgZ2N4fp2iAjGNA21wcJENmnOtK8lfu
         rceh4RB+Jtl/ehOX/qc+1lPCaoJUWMTsyQMguppm9NhFx01qU29lRgF/89hmxYUcDNRM
         b1ag7ZQw1k8dnJxKPCvBdZXVotM8aBxN3YuscDIWsO6aL+qaVQxwE4mzegVmfc0I25pa
         +qig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764681221; x=1765286021;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=K+4Bl/iHERcDPFKmyTAcsjAsPqCy8YVLMw2Vc1WCcPY=;
        b=i5pdfKVVaVAyNYfG4VBSZeD1QstmBo5XY1NSC0emMuAkSxWIqpPSIqvQ4OzKY5VICR
         eJIkW3UsKvivkdnv9eg3QFKlnX++Tvq6KIGVgouVfA8oDEp6DPyx4HVNYi5aRpzHlZi9
         xeWb2Fj2fUsZThTFHzS2rlN2qv4WpyWSYh433QQDvJqcVzZMQLuR2iqecmkGctTXVH8Z
         e8vczoYkZSY4QkCYIIFhCHtwVTIodk64tAHdD+POXNN80XMV/oyZtGtAwIXaiG76KBvW
         F7yovFiYUHPfvFq3WnGNLuCkF+J89TkkdCpNhZqwoQ1ehuOx6hlZ/0RujWOzlPHCxZIg
         3kXA==
X-Forwarded-Encrypted: i=2; AJvYcCU2aZJEsIHE8qOylFH4WvCEVmseqjy15Vz4YloaoFcsstPQBZDGnQl/W1Q+HQYXSgMSjPtaZQ==@lfdr.de
X-Gm-Message-State: AOJu0YziaaWDnVtR0+myHi/rBdNarSwMOhGtIth0f7uo19AUv16tyrBK
	kSIos/lcFglD/ifvaDwvDMSrAG1Yjbd1W2fko8ZrrJFtBCbr8XO79inS
X-Google-Smtp-Source: AGHT+IGdb5Jso01LMqs1gOV4aVKOvoQ5H1GU46Az/+dEoMlqMb5X22nxM9Wvsu+Uc6esUtqnMeiO4g==
X-Received: by 2002:a05:622a:190d:b0:4ed:6831:56bf with SMTP id d75a77b69052e-4ee58841cddmr616812631cf.13.1764681220443;
        Tue, 02 Dec 2025 05:13:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZjwKyiVvz15CmlID3+kRZEMTVXOb+YbPnd5ODbyngHsQ=="
Received: by 2002:ac8:7d8e:0:b0:4ee:217f:a9d9 with SMTP id d75a77b69052e-4efd043e2eels116115101cf.0.-pod-prod-03-us;
 Tue, 02 Dec 2025 05:13:38 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWCTtNOZp6nNOLQFTaXjMYT2bDoZIfxRtOLEXyBlauaZA20IJEM9OkaD4BuKU7IZHSnxZIcz/JttMk=@googlegroups.com
X-Received: by 2002:a05:620a:29c1:b0:89e:b3a0:bce9 with SMTP id af79cd13be357-8b33d1d01c9mr5793943585a.22.1764681218752;
        Tue, 02 Dec 2025 05:13:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764681218; cv=none;
        d=google.com; s=arc-20240605;
        b=QryH/kA0oDmeZPzE36Y+lVflCU3oAtTOc+3qrRm1IJniZdlg7W2F8uGCItXp5yJI8k
         zbzmJrI/nIUtXBeMB6K1xR5RS2b1vlmxGtlAT/o8SBOseYmPUrPuYvD9DO6S9QpqeXCF
         QqrkU2dAI+wsLlnD6U/9qIPdvcUJidXPCd8L+G49eNa1P+BO2+C125YlFnUE+FNyGLtW
         riDXZAEN31dXLFaYVz+ACK1upqg2GX3sTxVBS9crPT5Uwo6CxPZ7G5/26XX8m+IPq8Zm
         8GI9UeT0e+6SuhsIf5AoSBPC2uiELn5qa1TJCZHL+GucwHdFo9UZ1CUH2lkss3ONJf79
         IY4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=JsdSONDsYowfbOUGFHoi6ZdWvnnwkrdvfymRkfV+MPY=;
        fh=xTHc32sgji22pLXw4jg5uuhne9BUJnTGIbLzPxRaS9k=;
        b=BYhpbKZKZb/weHcdzi6JU01EEtxsrVdwDZOZ86VZWXI1f1T08qMeTEVtRNmwrGyCuJ
         UcYlcAjX1s41ZCrCNP9rKIKCnuVtssjAe/N12XNtc9drRJPGzCN6+kl9t7v+ISBvmQX4
         3rjcQLNDHHh/AG17etKcE2+HU8cG75BjlFdaQKwvXpceev5eSX5km/KKA5q9BFSy+m7Q
         2zbidPr26uQ3BtMpLDtKDx+bSlUeZeSjPxtI+V5FpWLR7yHhmn99/PkErsV0rGpRQByZ
         CdtLKDqa3WNBMhIrizXhA3rwfIPdog13avB0f/Uebjsg1R0zIc7YRjbfZGv7lZAgXrAr
         uc/w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="E6NDEt/W";
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8b52a1d430bsi45152085a.5.2025.12.02.05.13.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Dec 2025 05:13:38 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-604-q8bW6AE0Mo2R_347Dw_DuA-1; Tue,
 02 Dec 2025 08:13:35 -0500
X-MC-Unique: q8bW6AE0Mo2R_347Dw_DuA-1
X-Mimecast-MFC-AGG-ID: q8bW6AE0Mo2R_347Dw_DuA_1764681211
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 61C7C1977016;
	Tue,  2 Dec 2025 13:13:23 +0000 (UTC)
Received: from localhost (unknown [10.72.112.62])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id C472918009A9;
	Tue,  2 Dec 2025 13:13:20 +0000 (UTC)
Date: Tue, 2 Dec 2025 21:13:14 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: Johannes Berg <johannes@sipsolutions.net>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, andreyknvl@gmail.com,
	glider@google.com, dvyukov@google.com, vincenzo.frascino@arm.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, kexec@lists.infradead.org,
	elver@google.com, sj@kernel.org, lorenzo.stoakes@oracle.com,
	snovitoll@gmail.com, christophe.leroy@csgroup.eu,
	linux-um@lists.infradead.org
Subject: Re: [PATCH v4 11/12] arch/um: don't initialize kasan if it's disabled
Message-ID: <aS7l6gfOWvVpFWy9@MiWiFi-R3L-srv>
References: <20251128033320.1349620-1-bhe@redhat.com>
 <20251128033320.1349620-12-bhe@redhat.com>
 <86d982368a85ab9dde17e52b45e77f5f76efea08.camel@sipsolutions.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <86d982368a85ab9dde17e52b45e77f5f76efea08.camel@sipsolutions.net>
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="E6NDEt/W";
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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

On 12/01/25 at 11:56am, Johannes Berg wrote:
> On Fri, 2025-11-28 at 11:33 +0800, Baoquan He wrote:
> > And also do the kasan_arg_disabled chekcing before kasan_flag_enabled
>                                      ^^^^^^^^
> 
> typo

Thanks, will fix.

> 
> > enabling to make sure kernel parameter kasan=on|off has been parsed.
> 
> But I'm not sure how to understand that sentence.
> 
> And I have no idea what to do with this patch, with it being random CC
> of the middle of the series.

Sorry for the inconvenience. I am worried several rounds of posting
could bomb receivers's mail box, so only add arch's mailing list to 
CC in each arch's relevant patch. The whole patchset can be found at
below link. And the whole patchset are sent to linux-mm, lkml and kexec
mailing lists if subscribed any of them.

[PATCH v4 00/12] mm/kasan: make kasan=on|off work for all three modes
https://lore.kernel.org/all/20251128033320.1349620-1-bhe@redhat.com/T/#u

Thanks
Baoquan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aS7l6gfOWvVpFWy9%40MiWiFi-R3L-srv.
