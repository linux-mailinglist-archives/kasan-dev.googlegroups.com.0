Return-Path: <kasan-dev+bncBCKPFB7SXUERBZFQUTEQMGQELLSJAYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D6F7C90C51
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Nov 2025 04:35:02 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-3439fe6229asf1124406a91.1
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Nov 2025 19:35:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764300901; cv=pass;
        d=google.com; s=arc-20240605;
        b=FE/UK0mTbM65z0vgAh26aiaNWfr2ofORjqtwLK++RtSWFzY+vgFNJyeQGPyMnomLzH
         IkhnUzlKmIiJ2m1IQimmRkazFUmZagET6itWo9nzNuFUlzYkRt7gkZSvIkDwWlcwf9rn
         bmKLBlmloO98bCN/yQpnqcRCJxgRBwB7xcPuTekZN4ZELf6G2+4ZfH7Zitnd6r4TEWh6
         JbbMxRUks/xIw4gLdD+3+aGNiNFE+Nx2UwjGx5mXTqMADDtWaDDCedMfLPJ/UOTBjQwb
         IxZ56LHId8l3TW5t1GGeZaiDcPJEP4d4f/+5T8BIVYM0230NJYSCoWHq+qmRajOB9kMK
         YpoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=l1GjD/snYfQrUplEGlmxAmAS8TZ2egBttDR0Wa+jE1Y=;
        fh=gtveTj8GGaBuMeVnOAzn3ieTH2AfX9GxpHrOT7cOrsQ=;
        b=gJ7bmN+bgIZkNyffp93oCNDw/sMyJwETTuKRLKtzb9aIGRoSKM8F2jCDWV6nMmX4nO
         zukkeJ2nZopcFXLuKoCoqHQyBs6t9+Ut0SNgdwgh5/WNlnJ6/SIsgKRlRSSyLVsQEPYD
         mywlKK5C22HKRm2sg/s0RsicTDY3Z1hWgz4B4+C1DxQ/qQ8Oq3NIav/k6Pc1RoZpVCNB
         NpVK7qggDKOAZuofvWwRFWB0506Ry1J6rFW+hN1WogB/mCaJhiqKKIYO0uaPTY+pgrQG
         ER4DUXrVPHvX3gYUic0DkmxbHtnX748Qnsr4/W++KqqgU9hODsVERdMBIDqZxyauwCR+
         z/PA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=IOBh9EPI;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764300901; x=1764905701; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=l1GjD/snYfQrUplEGlmxAmAS8TZ2egBttDR0Wa+jE1Y=;
        b=VeXbNhREJ0CcoaklQsmYgde2Ee0KY2EJZFUdhfVhoaw03DCAshLb7IbBPmQfj31/XZ
         AHlpgCy8qwJadjVSjkHrwL3ZR/1IMJy8oEvyeCRrVLv7Tjp5YLBUup7TIAoX595Nrqj1
         lDvdDa0bmIQ2fgekkrH4RpZg5S496SolAEImvhfMC/WLwCM5TmyjhEpouXIdbsFiUHKY
         0Mq/RNZeQMESwjvbwe3M1ajNaDtTPzOlAanlnSxuTlw3nq88y4WHRFz42fXWhmho3hfM
         Lm4R+ccL8irO88iNQfYgN2nIxhu88uoKuxV2+Q6Gn+8IRgkEDVbA/PLklqkHouxd1kIH
         ajpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764300901; x=1764905701;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=l1GjD/snYfQrUplEGlmxAmAS8TZ2egBttDR0Wa+jE1Y=;
        b=MEnVc9sS/PTkAfHaJrDpE5+aProEDNidlELZT0rIBxhN3vUyaGHyjkiN6MfLfAsRNk
         ov+FzKoh166hNkXWn1blWpn+eNldc/XYVADW/L8z0bTCIOQ72jgrJ5YM2EULtbpNBsJx
         S65kBZRp2pegGfkIeZU+pH8W+JBR+gLzTYDiFc7h89D/i7BH/dQLzpTWJJgIOHmc9M3D
         6G+clvQvkHRmKeegq89gqx2T+SBOev63d7bpWlCG0TNSEhUJd/tq5I+93GODolmwd1EF
         UtW6keZzp4WQ2uIw/8V2qFK5jvE1gPPQCwOlXlz5sunpBS92DvlbR5WYo/cTBcTglbVI
         5mbA==
X-Forwarded-Encrypted: i=2; AJvYcCWMiuqYTACLkPQ5SbhNIAXnFXEbXg7Pmywh/lbWxs3PREbUEvirXAbVrYtzO2HSNazF4DBNsg==@lfdr.de
X-Gm-Message-State: AOJu0YyqXOZigKbC7mCShCXTUC6nAGQWI/bXJJbxmH0+je+HzatGqUy6
	ej+qfdcPaMvBdZl6xz0C0oMVBTn+iy6dq+g4Cp68QsmkFPbaOwXTbuwr
X-Google-Smtp-Source: AGHT+IFjunvtpOv05lb0fDNtXkcWJmAA1JOKcAy99Uw7Bg6D0l+ckh0GoeRtapRsJLCdTOkXLr/pog==
X-Received: by 2002:a17:90b:2e03:b0:343:a298:90ac with SMTP id 98e67ed59e1d1-3472976090amr30365533a91.0.1764300900883;
        Thu, 27 Nov 2025 19:35:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+b0oLU05wPlz+yQ3ffssFZ0H5uCqpcxyGssa32Xkngu2Q=="
Received: by 2002:a17:90a:6d8f:b0:343:6c06:640b with SMTP id
 98e67ed59e1d1-3476a4c23b4ls803318a91.2.-pod-prod-00-us-canary; Thu, 27 Nov
 2025 19:34:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXW2R6J6gBOB4yu4xd0n2Yuk/KUh5Y3uneBJxJdYJt20WwmgxCnA/u/Ld0tHLGqAgdwn+DVAH63bdA=@googlegroups.com
X-Received: by 2002:a05:6a20:7344:b0:35f:84c7:4012 with SMTP id adf61e73a8af0-3614f5a2164mr27935177637.29.1764300899127;
        Thu, 27 Nov 2025 19:34:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764300899; cv=none;
        d=google.com; s=arc-20240605;
        b=lnV3hyUaqw1BMagUV5mhifs8ZgkhqbCvicwmkoPFBuXgM/dwzrTz515YEmqMJo4jTH
         BZoq9jkXmySK+0Ehduv6hEwbDzq74cNnxGajsOBXK1BcMetU0lzl0nc/oP4GtrrJfnzl
         51Y+APwaEkzwG5wA5IvMbpx9HPcaTHeBP6//o/8KDME/iFmy40CSmdnVjHnvuJ880KDQ
         h5khfh9FtlCKWFSm9+jMMROU9mkVhkM8tUm29JcRKbyPTsqDDg+p1BBHX+I3Ec1kjdh0
         mZhTy3ZB7Yq4oh9y/sVLZXjsjL64hXgA9KTVsKrhTIhbbJ6w2H+lqGGt8vOgDoQdcHfI
         tppA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=K3b4hcMhxxjCn2BaG6Ly1WYT5S5cKb/IEvtIbpVbOV0=;
        fh=TTrOs64BUkjB75bl3OTQ6FkM11XT70u3nOQrfm9hLlQ=;
        b=Jsf/qrY7KLI/QTyhMmrh2+yX7dS1xqIlnuulHQJcsM7nwZLwq40yyOFk25pu6YP+b2
         88irWxOd6G5ZVINxK6KIPArvIP85Yx0zgfZJlGgbE/NEHX2H5674zo9/4bOiBgMgUpMv
         nu51P8OyHkTd7wn53SvaeiWbyFCPJzlfWm8/3o18ez+lmHdUtUwVwOfKSULfFhwoddHE
         oNuTFoAeGpiuojoAXEWv5Muevsli3SLGGYIh1SJbs6Zez/4Z+aTimHlgNtrT1gsnKgdU
         ael4GisZCFKtPjUXIyovOR86tVHcuGXiGDSiq7WKlfSiA8wJPLz+88HjaHXkBiFFCMDG
         Y79w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=IOBh9EPI;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7d15e6e2fe2si91538b3a.7.2025.11.27.19.34.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Nov 2025 19:34:59 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-509-Z-W1bC2_OWGpYgZiaAnmrw-1; Thu,
 27 Nov 2025 22:34:53 -0500
X-MC-Unique: Z-W1bC2_OWGpYgZiaAnmrw-1
X-Mimecast-MFC-AGG-ID: Z-W1bC2_OWGpYgZiaAnmrw_1764300891
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 0441B180057A;
	Fri, 28 Nov 2025 03:34:51 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.7])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id AE04C19560B6;
	Fri, 28 Nov 2025 03:34:43 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org
Cc: ryabinin.a.a@gmail.com,
	andreyknvl@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	kexec@lists.infradead.org,
	elver@google.com,
	sj@kernel.org,
	lorenzo.stoakes@oracle.com,
	snovitoll@gmail.com,
	christophe.leroy@csgroup.eu,
	Baoquan He <bhe@redhat.com>,
	x86@kernel.org
Subject: [PATCH v4 09/12] arch/x86: don't initialize kasan if it's disabled
Date: Fri, 28 Nov 2025 11:33:17 +0800
Message-ID: <20251128033320.1349620-10-bhe@redhat.com>
In-Reply-To: <20251128033320.1349620-1-bhe@redhat.com>
References: <20251128033320.1349620-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=IOBh9EPI;
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

Signed-off-by: Baoquan He <bhe@redhat.com>
Cc: x86@kernel.org
---
 arch/x86/mm/kasan_init_64.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 998b6010d6d3..d642ad364904 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -343,6 +343,9 @@ void __init kasan_init(void)
 	unsigned long shadow_cea_begin, shadow_cea_per_cpu_begin, shadow_cea_end;
 	int i;
 
+	if (kasan_arg_disabled)
+		return;
+
 	memcpy(early_top_pgt, init_top_pgt, sizeof(early_top_pgt));
 
 	/*
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251128033320.1349620-10-bhe%40redhat.com.
