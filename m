Return-Path: <kasan-dev+bncBCKPFB7SXUERBD6HY3CAMGQEGJUDWXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 456ABB1AE34
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 08:24:17 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id ca18e2360f4ac-881958d756asf26328139f.1
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 23:24:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754375055; cv=pass;
        d=google.com; s=arc-20240605;
        b=EPPMQGy/VlugrizJ1Vmdil4VKvziwqXwE+5F+BETnnRLZXkVgiHcb3YFfzyHfoeeCz
         q8sY959WWntqZeP0CSOEfYR6dNYUN4Tv0q0qY2PPg2QL8ncUpknKS5Qi8o0dWlK4z6Yw
         DpajcMGpdD7G3Hwdru0zRHYupZ+BY7qSuFM83yCm6GQjGLjzGoyuJ346jX+5G9sg5orf
         zLTMqzCtzXlBwi2grihkDNis3s0Em0GqeZabVQRGl43XKiPaKD5/+r4zlimhVuyklpdV
         6ifjCJ55WfUXHyOcm0S1czhkCcbaJYXS8wIiNGKHigG8IECpd6AwiqgwTfzvs6f7GMAK
         18xA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=3kkOm+iVm5Ffzt7W2cFZSTAS9bgQVDWJSpMfP0srCOo=;
        fh=m2C3pnCwlU1S7kCBVY5/303SAcaBVYRgbKMSrQi2ZYg=;
        b=FrjeNcohAJNFnGHrohJf+nX5jsX9wHxOSXjgAntmib0PKKng+yeseQVJsR9Qsr3L+c
         HLuz77pW1ONtbHkBmx5l9Vv01RoI0AHRvBDGsSZ5jhGF/0LuwSn4vRSJs0TMK2dpu9Ek
         M7JdGYQrWyERsLlRoZgXaJmt+fbopfT5kWRB8EJYCCy6Vg00jEOHWMH0zxDr5ojRTWre
         wj8lRBR4uAnU9zXvb18SXqO5HLf4g0R+wFuyPlqY1pzciug5Lc12ftAzzfPCG0NxFL8t
         qHs3lFBaVJGZbQJce6gzUzd6EHozOMEnqbCLrkG/QgY9+E+bmXKhuE73hVngJ5pKcu9W
         vc8w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fzNTvYIT;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754375055; x=1754979855; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=3kkOm+iVm5Ffzt7W2cFZSTAS9bgQVDWJSpMfP0srCOo=;
        b=b5QCdx4Hkvd6pzCzW/QYjX/eN6eyXY1s4+R1RaQg//pRS+umTYmNSAy+LzjMCj2wTl
         zKlDawzbye0rzcbKfdxe9FvLBuCalKFncoFfEzSUdciYRPfrJJcxaF581nYLeBCdhiQ0
         Ar77kruTZdG8Tp8HJ5BUneeXanJzdU8I5wqo6XVHqWlpgVZyQBZhMUAdGnIxKZzQbrNp
         zF2XWM2ARXeu0bAa/tS7lR/OBFAD71BeMlx6yKRjUK0JJGgn9EmY8KV4nUX3cwOasagv
         BbGL6s2R5ieu0G9kG7oJnuVyaixoxTXXn+8CgdNbfByZh8unY/qjB0aqTPCOXpz85kpQ
         SATg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754375055; x=1754979855;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3kkOm+iVm5Ffzt7W2cFZSTAS9bgQVDWJSpMfP0srCOo=;
        b=jI3szp87todwrMZM3WgmexjxRMbe7eUW5rVt5Iy77fjiVufqE8L4v+jU5LKT+5tvfV
         KY5mhUqJGa2sLQ+z/9/RRS04J0IuOEPA60ex9q5ZPOlHAOhB3P5JhMhx8MQLW6GklJTd
         CtPzRzn9DmUsYF3jfM3zLGsDXHuxOUg7L9yd4WVZeWTzFwHsRsc7C05fp6fcg+go8tO9
         qL8eTUDodLYvT6GIye3ty2e1YdTarvFqa2DKNCC5I+Ntap9PZ1SbTKzX7qDDJe7NdJ5C
         A4B1ortAOc0d4g+lfzo2KK2nFd7kup5fY9eqWn5E1SCXnEBOk56OBZrpDacXGJIxlBc9
         jRrA==
X-Forwarded-Encrypted: i=2; AJvYcCWrE3RCwvL6YAtjKQn4YfrsLlJw4Emx+MO684g7gUJMk6G13lvpivrFt4kGvpEdkYmdPG96lg==@lfdr.de
X-Gm-Message-State: AOJu0Yz4hXHGzYu1u7IBEsom3RUr8LQ/9IhHXCFovWTmfPQfFTF0Jama
	GOiWTxl1VeqaNTudZLzbIpUAWCae/nT8y5OPrYgHIZjKMUa5ztqv+Ui3
X-Google-Smtp-Source: AGHT+IF95I9l25Gn/wDcdu3Hlk10gQBIaVIyJqXH6SmGQL4YoAkhlVAhipERC2xXkfsCH+1nPyvn6g==
X-Received: by 2002:a92:c266:0:b0:3e2:9f5c:520f with SMTP id e9e14a558f8ab-3e51037e02dmr42681585ab.3.1754375055562;
        Mon, 04 Aug 2025 23:24:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeKUF0TmMrNRMoFeAuzH5lTchQBpHGDLugGi3hJPE6muQ==
Received: by 2002:a05:6e02:3421:b0:3de:f0e:a80d with SMTP id
 e9e14a558f8ab-3e4024dc23cls25360925ab.1.-pod-prod-00-us; Mon, 04 Aug 2025
 23:24:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV7GI8dS5ZyoYsxIqOyA5ec4nB3FusQPx5j40Y+hvQ1zExRJe/fP+qKFJnnBHO0E2NiXDgSa1aDpuQ=@googlegroups.com
X-Received: by 2002:a05:6e02:4410:10b0:3e3:d304:10d6 with SMTP id e9e14a558f8ab-3e51044c9fcmr26278935ab.11.1754375053563;
        Mon, 04 Aug 2025 23:24:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754375053; cv=none;
        d=google.com; s=arc-20240605;
        b=afQVthGdMoPNtthZElGWQPFP03m2xU5dEhg4J1SbwXBEPkgBkR4EP1YGoQfeMoBF+v
         c0DaR9aWnoHPoLAwer2glHLy3V6ENGvS+l9PmtuxiMbXk3gNPVrIbFcYSknyE48Q12oI
         iwer+NXQ9H9kNwCVi0fqTVRHI2T6LpHVeMHxtnr6qb8iIymiQag3FM/N4GaKBvgPvfHP
         cgXqhCwBm0UVgiwB7cbH0BrQSGbcxDZCKLELbWx/Pc+l7W4+R6aKQLf+BcXCNVmSMMFm
         Ld8VEhMCQFXIfkFNS4VjFSGuk/OpQ/hhappnpG7bX4kb3AwOB/KLf/+ZLqCUZHQg/r5X
         Y0FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kJO5yIBXXOgt25+uyQhOeCpPCqEaTDSwq6fQ38qy9Bc=;
        fh=zdgUGJ5AVcpjW6c3+faZMlslsU1+4WtDOSxOnvwQO5s=;
        b=hMwtiWccPzt6DbD0WUVWfnjSYhkUoOyxhBkgYrbHo+PYwq5iHrIvuNudXi6aTPvpL2
         lj/xYaovHDZcda3bFdemqQ3kmE/+kJYyDcXdOhCuh4/ESRo9ypFdr1+OIevgb7VKmr8o
         KK9uJIScPt/U14o27Pj1zw3pOfKJSLBNgZtHgXgLi2EaY1q81Rh+iazoT3Sj4C4bF1Cf
         1+qy1hE+sZ2+82Zy3ZlHLZAAInn6G+4FMC3s/hrkdrB2JHpkp1KMnIyZILuu1P4bKeL3
         SDy8ziv/unjSZ9iJq+z1Flo0rTTKz8s049mD9MVCAiefbzVuNZG5yCnOEYmzRuB2bX/Z
         Y35g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fzNTvYIT;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50a55f3ae47si563081173.7.2025.08.04.23.24.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 23:24:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-178-AR-aqPXUOv6YUb-9IY0KQw-1; Tue,
 05 Aug 2025 02:24:09 -0400
X-MC-Unique: AR-aqPXUOv6YUb-9IY0KQw-1
X-Mimecast-MFC-AGG-ID: AR-aqPXUOv6YUb-9IY0KQw_1754375048
Received: from mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.17])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id A0AF61800876;
	Tue,  5 Aug 2025 06:24:07 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.136])
	by mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 6C6CF1956094;
	Tue,  5 Aug 2025 06:24:01 +0000 (UTC)
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
	Baoquan He <bhe@redhat.com>
Subject: [PATCH 4/4] mm/kasan: make kasan=on|off take effect for all three modes
Date: Tue,  5 Aug 2025 14:23:33 +0800
Message-ID: <20250805062333.121553-5-bhe@redhat.com>
In-Reply-To: <20250805062333.121553-1-bhe@redhat.com>
References: <20250805062333.121553-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.17
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=fzNTvYIT;
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

Now everything is ready, set kasan=off can disable kasan for all
three modes.

Signed-off-by: Baoquan He <bhe@redhat.com>
---
 include/linux/kasan-enabled.h | 11 +----------
 1 file changed, 1 insertion(+), 10 deletions(-)

diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
index 32f2d19f599f..b5857e15ef14 100644
--- a/include/linux/kasan-enabled.h
+++ b/include/linux/kasan-enabled.h
@@ -8,30 +8,21 @@ extern bool kasan_arg_disabled;
 
 DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
 
-#ifdef CONFIG_KASAN_HW_TAGS
-
 static __always_inline bool kasan_enabled(void)
 {
 	return static_branch_likely(&kasan_flag_enabled);
 }
 
+#ifdef CONFIG_KASAN_HW_TAGS
 static inline bool kasan_hw_tags_enabled(void)
 {
 	return kasan_enabled();
 }
-
 #else /* CONFIG_KASAN_HW_TAGS */
-
-static inline bool kasan_enabled(void)
-{
-	return IS_ENABLED(CONFIG_KASAN);
-}
-
 static inline bool kasan_hw_tags_enabled(void)
 {
 	return false;
 }
-
 #endif /* CONFIG_KASAN_HW_TAGS */
 
 #endif /* LINUX_KASAN_ENABLED_H */
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250805062333.121553-5-bhe%40redhat.com.
