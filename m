Return-Path: <kasan-dev+bncBCKPFB7SXUERBJXR5TCAMGQEJJR4KTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id C2EC9B2275D
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 14:50:47 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-7098e7cb2dcsf96872766d6.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 05:50:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755003046; cv=pass;
        d=google.com; s=arc-20240605;
        b=Cjwmjtdttw3RskEtGZvFQ9ENk7ZhdLdcc64+G5hxkZC1WNUCt/wDkQedcRffBHism/
         GpsDbNjpz9G8H6ww+6DGG4cNdxWOk95G6gCn8w1HluQC9mSqIbqk4Gk29+e7FW2gFtQE
         AyPkuuwtWUCZcysT720d2gswayyw/MRnP0+oOhZPfrSH92SxCi5eMJidO6tOXlEiv8/W
         Cx2MYizn1WH6h6DrBwF0O3c5KyIWga3NYAdRmmLfrXvJjUrYwFGwoB/dywcQictny/CW
         goTNYyXEFsh6aocfwHQQIQpHyORcBX29YRLNgLe7H25ECxbMNPWwYi1UpuY98wVRFFOW
         PNtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=3ahdhIo5NeRGzrlTIdtilB/XqZPiTt/G1egww2ILnf8=;
        fh=EwGov9j8ifwRybj6nVhLj79ycPr/ekG34rE7w+YdLdM=;
        b=Fd2KU6fEuan5ckw5nseYa/XRm7D5Kd9AcC5hDWvkYqQaJ28q7QzK6cqta9/nbW5ZMM
         eVhy0I4qhN4qcJSRgP+MaGWunD5txVz7QeMbRYtJDYauwH1zqhK1t9fRuPK0OK3BVNQ2
         PwuTrW7Igna2m2omWIwqFm9mmjjgjzHzarUPLNZ/tHKBXbhbWwTWVeyW6N9JCCY5+RyT
         T6uDo6p4QNLCkBWZoxirnOC4mfOFOVhkWtm1dTWPrg2gsAv47/BBQbF1uScSnZkpR4xh
         mWK1UVGgAycK8/XfpeeGEMYXO1J4DCxvgILE+Qnhlm37VE3NztFb/sRSlzv2nIbRjC4a
         b7DQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=TVXgkvBX;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755003046; x=1755607846; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=3ahdhIo5NeRGzrlTIdtilB/XqZPiTt/G1egww2ILnf8=;
        b=Q53yqq4FKDaSnxIFuT+Nw1BZO0eDQ3xLAnshdDoP923UVTpzdcyRPjUeVuQ/DNktC5
         Gu+DGnvsoDGp/Q9dqt9pU4zoKjYysNLVlqyV98I8mxSgFEMR2nXbknKQadF13Db6WW9t
         BG+x12m6VgPZvnyqbr2TbyW6Cpn3NlWRDQ/KHqkcvfZV0hGXBNxCdg3cs3lQPhMEFF8U
         pUoWBCQ+pdeepRerC5QjrmZP9WHRSzqBHDYo+mkJXnVXVHL6nS1g8tMhCD8E9W/wKNZw
         c86caNy9cnICosY2Pve1CIdllGUdqKQtlvKfN+v0aofTj81UHrDoUXTS8aFs7N5vPBhZ
         a3zA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755003046; x=1755607846;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3ahdhIo5NeRGzrlTIdtilB/XqZPiTt/G1egww2ILnf8=;
        b=W70Xq8A+7FYH4PNatFVLf6fMOh9mv+FeMa9PxJos5R0exNc7Zu99X25W+pYR0uNu0M
         wd1rAAzrpuCtkIYzwWcH9GwGXVOqigWMu9o+Pj40mQGcgDv/x0V4TrIp1NHxzZj18az0
         7EJnCUIGimo5uuu3phiqcy/xX8FeoVP/YCJxT/gqiPH3oya62IKbut4aUVyFtl2eKUz2
         w1fo0bmcezyqd8yiJjgyI0i9EkI90pO8w/VC8QIFL/PeZ7aeSCrR4JE2fPUHf5v4g4dx
         YfABGVfci97hZEJEQIVPR2wGEQx5fzsl4xtMb1tAv3aOEs8vi+UYOjlnk+krzHb2PGCm
         7BtQ==
X-Forwarded-Encrypted: i=2; AJvYcCUw7GQjiLcbUFMUeFs7F+dxGtkLIfL33qTkdQ/T/BBrPi8wL5cIAog1KlZRL2kAmG0+Aq1y0g==@lfdr.de
X-Gm-Message-State: AOJu0YyBdc5IZcibvtq0teckZiAAsCnd2hcI4TAUk5gSiFiKsmuF9lFu
	sudwlZAEnPmgkE1eQ5WbA/u8AK9cOLXh/frdXpe6IFQ3Cy35MJgVB2Q4
X-Google-Smtp-Source: AGHT+IHyY1gcM17ONbtpoAlTfeYnMVY4cEBpscPWUhdjGe0ZFpSj/Dn2V+M3Pgfh0Y59gaZnjs34yw==
X-Received: by 2002:ad4:596d:0:b0:707:3b3b:4e9d with SMTP id 6a1803df08f44-709d68fe66fmr46076486d6.18.1755003046429;
        Tue, 12 Aug 2025 05:50:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeL27hT4jNFYm5SaYrFxGeQwm/Pjj2euraH7tg+xDk/Yg==
Received: by 2002:a05:6214:c2a:b0:6fa:bd03:fbf2 with SMTP id
 6a1803df08f44-709880a9f89ls46850116d6.0.-pod-prod-00-us; Tue, 12 Aug 2025
 05:50:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXKagZIGyn2HYFpogD4qXh/G8ufJkK0BcI6mlgYBKbtL+uw2frAPbYdf3qXwNphwxdtCj1CS8I19qs=@googlegroups.com
X-Received: by 2002:a05:6214:2b0d:b0:707:2b04:b038 with SMTP id 6a1803df08f44-709d69feea7mr46106716d6.23.1755003045672;
        Tue, 12 Aug 2025 05:50:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755003045; cv=none;
        d=google.com; s=arc-20240605;
        b=FR9x8Ahz215ZHM0AZwiUXarb1dLiPOTQq8o398HnIdxw676AEAGBw6VwLb4UtYLN4P
         T2lTSrbTRWILI6NNt59QELmEA8SWrfj5vZfdpxa/INm4sGtjSfJbd7m4DCCN59aEI1hC
         wXfnyJ2pWO2DbutbBjICAdNr/8cVmHjL87gNka5wr49FvlnRSJpNNjHiKw7qwgKjE7A8
         ZlyDPxy25dc4p9XKsh5ETO/ge3uEFbykq8fHbeFkdRjlNR/Fkxt0kCDYxUfsrJ5w6fjl
         2XYQoYzgCY3vq37gcrsKroB4V/JSNfXAlK6EW9CcyyLFZYTdYNrJebkoagICp4PcjR4B
         P7bA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=QN1Z1dUeks4QygHE7wKCYxkrDkPOGTvp8PG+uI+E7oo=;
        fh=ZQiobZ3avnYd2dMV0+zhbhF+LZ041TMixvjrGLjsPak=;
        b=CePpq631gcKymQDkliALPCFDAEZM+TLIQ7dkcT8ExhkA31md/snVbHVbkZ0yHlnGvk
         vannDj57QSNWOB6eVA2kVvF1LZjoIyCtph81goUqUdBM3i53DwnG957SFR/ybzrP1cCP
         MJ0X2rXzWF+QiKBeVP+PPnO6spwE7fbGkm1BGicEq2fD8SE3QFCpCQPxrLVJTZKjG9Vr
         xOyBVA2aF8QJbuinV/8PQTjTrTHwB5dDP3mBaC6dUxO3vdicn8ilyCY6TnHDLKfRW2I4
         ZU0QhjBXI/iW6209wyteEZhaAn87ZTTlS0RPv5PLF0cI0CZAHrkn+Mlt7Va/n8giy7Jh
         +Pmg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=TVXgkvBX;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-709b56a99f2si2408786d6.4.2025.08.12.05.50.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Aug 2025 05:50:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-620-at2M-5U8MMOmrD3AvQwZ7Q-1; Tue,
 12 Aug 2025 08:50:40 -0400
X-MC-Unique: at2M-5U8MMOmrD3AvQwZ7Q-1
X-Mimecast-MFC-AGG-ID: at2M-5U8MMOmrD3AvQwZ7Q_1755003038
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 4CC9C1800773;
	Tue, 12 Aug 2025 12:50:37 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.156])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id C2C97300145B;
	Tue, 12 Aug 2025 12:50:30 +0000 (UTC)
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
Subject: [PATCH v2 06/12] arch/loongarch: don't initialize kasan if it's disabled
Date: Tue, 12 Aug 2025 20:49:35 +0800
Message-ID: <20250812124941.69508-7-bhe@redhat.com>
In-Reply-To: <20250812124941.69508-1-bhe@redhat.com>
References: <20250812124941.69508-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=TVXgkvBX;
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

And also add code to enable kasan_flag_enabled, this is for later
usage.

Signed-off-by: Baoquan He <bhe@redhat.com>
---
 arch/loongarch/mm/kasan_init.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_init.c
index d2681272d8f0..0c32eee6910f 100644
--- a/arch/loongarch/mm/kasan_init.c
+++ b/arch/loongarch/mm/kasan_init.c
@@ -267,6 +267,8 @@ void __init kasan_init(void)
 	u64 i;
 	phys_addr_t pa_start, pa_end;
 
+	if (kasan_arg_disabled)
+		return;
 	/*
 	 * If PGDIR_SIZE is too large for cpu_vabits, KASAN_SHADOW_END will
 	 * overflow UINTPTR_MAX and then looks like a user space address.
@@ -327,6 +329,9 @@ void __init kasan_init(void)
 	csr_write64(__pa_symbol(swapper_pg_dir), LOONGARCH_CSR_PGDH);
 	local_flush_tlb_all();
 
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	/* At this point kasan is fully initialized. Enable error messages */
 	init_task.kasan_depth = 0;
 	pr_info("KernelAddressSanitizer initialized.\n");
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250812124941.69508-7-bhe%40redhat.com.
