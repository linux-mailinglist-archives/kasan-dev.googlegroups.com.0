Return-Path: <kasan-dev+bncBCKPFB7SXUERBDPR5TCAMGQECIOYPEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6111BB22757
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 14:50:23 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-61b703695c7sf4505087eaf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 05:50:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755003022; cv=pass;
        d=google.com; s=arc-20240605;
        b=afpHC+CCEcBnHrAuUadAVPitCQ1oSfuUCEPuaVoCYfvFYvTU2rMRZ3k6HMDe32mzZ2
         fsAWkFioYVB0K3Y6uqNg8p5svkOCOhQZlXEYN7xowhSL1i19gM5q+SvXtJQ0UaE8wY+9
         +rP1CzgpwjRsaLSsH7Ms8NvNtiygBy6LaTKBneQuvT4OXvJtTLqC4FG/wPckRewGM7fM
         j3V7ECV6eiEyxL2UIxxuMit0VqfYeBXR96KeoGnO7HN5jEmzKK7ESDFqBWvvkwSPrgb6
         o4V/wqUHvC+fgo+8LZnAhySMlVEqWiG6j3gmW/t07nTwm2ICdPE6Lg+52G8W2Z4AT1oy
         zS/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=lDlnJ5vF9gKf7gnRXq54OG9XtXBZeoYjXUUOMPiS5K0=;
        fh=vbWDbf7d0IZDndExLKmoCDkkAg4hkv4I/15A0VjFD5Y=;
        b=IgOSI6yZLb70yQLCyT0sJ/StKKFnoZi5cVHxW/3X3LxP1TOnYrUbeeB5qcu/w/+izk
         2754fom52RTlQU8RqzjX1lupEyqzZliZh8DYOyf52f0pXf8sagfuxMA2eQv891NSdzBO
         5HUFEyLns5byXMQVbDNdT7zarVIJghHmJsdW9tNSTxKqRYl6fcOWcPC4rd4L+zOt2UoZ
         DEyizR9yPImFYxw3RpwdC0hqh+o4uuUNMzl7jjyCfupLjQ/a3XKdSxiDJBZ1uuET3xLd
         yKTve5GKRBFtBlsC2018h7Tzj3Sf/sEvrAo5pLAfSPtS/DYPiKKIUAEzdThtE+EuQAE5
         vjlA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=BbF9ulPT;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755003022; x=1755607822; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=lDlnJ5vF9gKf7gnRXq54OG9XtXBZeoYjXUUOMPiS5K0=;
        b=DU5BVvXB03ZI+tTEK+Z0uXQVh6b4Exh79FrFFTNkk3iFR/rWBVIv3QZ8PSwuIwHzuz
         PGHnicWVE2f1eiTw4ojb9ZUzVVYMBK/qVqqHtk+0VXJiptNdFwo8Zmx2cdZ7UhOW2AC3
         sUxDyUdsq4RvHnGpXvMHcQpX1JELBC26rea4NcOjdxvxhap2gtQ7RK2Qe6Fl5Mo9W5Df
         moNu+2iwjPDnXYLAVOxMjZVDeqEsGkOC006LmEfLo7XY3OvJLGQpfxkbE+hwIsqRJc1D
         orq5AyMce1TmE7nx2Ga6ddWmgBnn/xyAHU5nRjpWxhPPSg6f9xT6R2b1T3lOybnFq/kX
         soeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755003022; x=1755607822;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lDlnJ5vF9gKf7gnRXq54OG9XtXBZeoYjXUUOMPiS5K0=;
        b=PKBQ3glRKtWXPrHaRCASWQXMGwBd5G9yx9YW1dvL4kMaxZsUDjnbFdX3MUIF/rpexG
         MuJNIlngo6OvHzVIo9f9A7NaUr8r6MlhND0mSoDTTbUGqQO74TNA0PqM3qiY768txMEy
         WyLqUQl+BmeMdSyC9PMpBfJ4wD6XAZji5R7o7vrc/1JMVRCva8cxyOvpAXDYLdgLF0sb
         1YaMQCJgnpSk4bNCdCFFp9Fxby6cMB1EeddV4+l5QdUeCcsFDBNPcJ5hIFAWHmbSJXNj
         W87ZuArXTeKPwSLXRsHbXfwayDS5aFkyDpbOZe8lB1fqjkMnMvU3deMDaH1iYBjeZoPy
         nXCg==
X-Forwarded-Encrypted: i=2; AJvYcCVpJMGzvhjStnJyRfgCASc1HH3vBV0JUJm/B4GjQinD7U8v8bJa/zc9yoQa23SEmxST2bkjFw==@lfdr.de
X-Gm-Message-State: AOJu0YzaJR5xAyhRBadn4zc4/fxpP4Bx+SnPEFUb53GzXpS03eCBzxy0
	aN2EDn1KtRDm2DsoA5TuroDXtv1HdngZ4x1aJlIlqcUpGMLn8Sm47EOV
X-Google-Smtp-Source: AGHT+IE5oX107x3HmDjQH4mPxEHqfyP1ga+A02Pj1Ccg3XvSmLcEwYrivkuRew0cyD712xyY+1iOAw==
X-Received: by 2002:a05:6820:2289:b0:61b:9c4b:4fe2 with SMTP id 006d021491bc7-61b9c4b609bmr4407478eaf.0.1755003021981;
        Tue, 12 Aug 2025 05:50:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZccHwu+fF8Thh+48wIAlBVfDFtX0rKDkLx9NegocrN7OA==
Received: by 2002:a05:6820:c318:b0:61b:a7e2:da58 with SMTP id
 006d021491bc7-61ba7e2e010ls277579eaf.1.-pod-prod-07-us; Tue, 12 Aug 2025
 05:50:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXf4XzQS0qjWz+k7v4a6DIYmDjUHxa74r8S3HPS7OI65qUEqwGbz3KLaj2LyDYt2G8WGv0Y9upUlUM=@googlegroups.com
X-Received: by 2002:a05:6808:2223:b0:3f8:3489:d93d with SMTP id 5614622812f47-43597d351b5mr8972189b6e.25.1755003021188;
        Tue, 12 Aug 2025 05:50:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755003021; cv=none;
        d=google.com; s=arc-20240605;
        b=jE6rx11b9IBXqPGgW6fqvNTcLE9cbypAFxDGKAo56rGIVvlMe8lgQsmo6CA0LysSdA
         ULDP54I+/gP7+jqX/lzCfaEGk1IzqqrIg+xgR2Pj2ln/elSkOuzQKdtjZwPMHMS7Kq8O
         GsZ2mTq8UyHTzvEZ+25cuBralKwxgs8B/UApPsAT4P96JGAJ8dOHBef7Duqf1hBlnKz7
         vRu23DVl2RlCxMHcGaKQHCgAHjwfVKlcNJSxOQZUpQccc1o0oe6R/UOY+IiH4Hks0fHr
         JwiLynB6DblafMnYyH50EEZTn+UuNn06ij2EuVJlS5VLRjZaIMZibufUUbamQTB1CWlY
         ZaOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lC7gxKLfCffY1/zE+RJo3yBumyZwu5V9Ft7avRiVVTY=;
        fh=ZQiobZ3avnYd2dMV0+zhbhF+LZ041TMixvjrGLjsPak=;
        b=kZPLoT3GETUXmuUcWSiy+sCc6TJ2dgCHtfSTwNO5N2W0P5Rw3akSCBlzq0sedDmei9
         pFTbueNcyPCAP9MheRr8yVGP0dKFdcdFp88NNILiynmkkkPsAkBpcHAEuKetyVtyerSC
         h197DOTkMkJAiIERb05sWeg9Ym3GCaNukLkhk37SZPFaqpOMPv+a9ErNPHFEFJ5+nwA+
         3IdAk7N2BRR25+X0+C4hM1806m2uDGqAcTiyLpMNL6mX4HU8u7E1p0Omg2MuheygDSF+
         CB6q8vU254vgxrpKiR2mLn174o49w8UHYej/ylbhWDydtGNMUVAPrLFfBbVqg6OiByMY
         wEWQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=BbF9ulPT;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-435ce56c67fsi42162b6e.0.2025.08.12.05.50.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Aug 2025 05:50:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-121-Ahe-8VyWPdGdPbA0pY0ufQ-1; Tue,
 12 Aug 2025 08:50:17 -0400
X-MC-Unique: Ahe-8VyWPdGdPbA0pY0ufQ-1
X-Mimecast-MFC-AGG-ID: Ahe-8VyWPdGdPbA0pY0ufQ_1755003015
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id F3E78195608E;
	Tue, 12 Aug 2025 12:50:14 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.156])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 173963001458;
	Tue, 12 Aug 2025 12:50:07 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org
Cc: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	kexec@lists.infradead.org,
	sj@kernel.org,
	lorenzo.stoakes@oracle.com,
	elver@google.com,
	snovitoll@gmail.com,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v2 03/12] mm/kasan/sw_tags: don't initialize kasan if it's disabled
Date: Tue, 12 Aug 2025 20:49:32 +0800
Message-ID: <20250812124941.69508-4-bhe@redhat.com>
In-Reply-To: <20250812124941.69508-1-bhe@redhat.com>
References: <20250812124941.69508-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=BbF9ulPT;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
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

And also add code to enable kasan_flag_enabled, this is for later
usage.

Signed-off-by: Baoquan He <bhe@redhat.com>
---
 mm/kasan/sw_tags.c | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 01f19bc4a326..dd963ba4d143 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -40,11 +40,17 @@ void __init kasan_init_sw_tags(void)
 {
 	int cpu;
 
+	if (kasan_arg_disabled)
+		return;
+
 	for_each_possible_cpu(cpu)
 		per_cpu(prng_state, cpu) = (u32)get_cycles();
 
 	kasan_init_tags();
 
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	pr_info("KernelAddressSanitizer initialized (sw-tags, stacktrace=%s)\n",
 		str_on_off(kasan_stack_collection_enabled()));
 }
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250812124941.69508-4-bhe%40redhat.com.
