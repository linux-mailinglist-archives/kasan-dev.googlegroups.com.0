Return-Path: <kasan-dev+bncBCKPFB7SXUERBMVQUTEQMGQEP3LQE2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id C8AA7C90C2D
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Nov 2025 04:34:11 +0100 (CET)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-3ec7ae153fasf502993fac.0
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Nov 2025 19:34:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764300850; cv=pass;
        d=google.com; s=arc-20240605;
        b=QdOe4E7qZZguv4Io9dKI+7AaEmXgSyigoPENymLktfkrJNCwdr1Cb6nSbA57V3Guvh
         TJqZD5L0Fd3LE/s+eVIUMZtgL7bXVU9ogZG02SEK2nXgsj2UaZqaJezSmxrBHjDz8uW+
         NQ9ukOB7CXl3Lel/W+ejR9qZC6HuGKs0P1EpuARQowmx0GXQo6MyI1sJUhh4lIeTyY/c
         /dl7alMY+xk7SfHNhuSWoyAwwEt8kbI9KNJ2Rv8OGXJCb0HipaoxqnPuXfRWw3rHRL4D
         juB9N9/5GC9jO5mOWukFAJmF3If/5KcM44556yjixyyGU5mCw8OZPL/d63GJ8bG2yEJG
         mr5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=zpyFCZZqhGoooO1mmz2nHDjUWblF5EotWtZEyFyrC2M=;
        fh=CAa43DPv3ej5BKnsAlhetjVmPJ5uBGZWrqFSNSdx2zc=;
        b=Fmqb4Mab0qWeZHaKpBB5/RU+XdhK7PLzHRD5jyYwfSxP4JRByPOReGDhsFMGBzZsgU
         sb6m/+u3x4w0ijWY0/qo3mvn2KEt5f7cEVF0CACHOqCmCSU6MrrRw8LfSVrMBCiJmmOv
         hsVnLN2szFswDMAUBHL1iHnOUC2JYMGDM5yziPBSH6/3anut0ADVwgerRtpOoFs9JjpY
         uat8Y9qzyrOY27yEYWAO24SsQmMzixG7EtFdhHllz8K9M78xQQghD05mATsY/x4pnu+n
         /EgB9AoX9zaj8EEiwxOtmncU5+HHd2NveHpj1AC4Vb084KYiTQioaB63Rn5S41IjAN9s
         cMLA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Rf86DUHD;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764300850; x=1764905650; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=zpyFCZZqhGoooO1mmz2nHDjUWblF5EotWtZEyFyrC2M=;
        b=rzyyACcFFRj3YmuN0y8SSyOpRLkpUmzu42AZK4cDABf9Cw+AfhHDWFQ6LzX6bqO9gH
         4lqmByWWpAAf/Wf4zz8RhqgFbL+/tZ+L+6KA0asylLxr18E0t8ID7gGYJKjN1MqFGZiy
         AHys/pxKN2l572dsFrBmDhtMczrFdnjzjpOOR2+2ufgcFQ8062fPGMshL62INWQtPPPE
         DkRooR6uRc0GZj0yzOKa0tu4CLlx5dEyeyEzJZukfuYCpufSTf1NwrDwmIQHE+DohBb9
         r4MPukdnxjnVkSXUmvRknoyJM3RtltELDp4H393W7KK3GbK6E8rM8gdLJAaDDjngjLjr
         u09w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764300850; x=1764905650;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zpyFCZZqhGoooO1mmz2nHDjUWblF5EotWtZEyFyrC2M=;
        b=pRChn3Nt20sqZg3yR6dmzR7tKTtz7VWVCSqnkljpaYAt8q7TBlGF2MLklzuPu+8RDL
         67zkp3FKoFNb3nQF2eT8a3dSKWbWGRcX8srHqCyveEGBuf2i+8Ws85pDfh6cMyLUV24w
         MG51N8h4wDzmZjR3BbNGkImYedWWPIWQnzX31u15jeny8txhIjYGjjPI+6nCvfnLrmiZ
         uMBjPowQWM2C3UaDccPWli19vt7y1fEwIMXQuRUZapaDxIr9F/pe6fzN2QrykyHjPaBw
         I+vvFKkc4n1rHtYG0OaCdG5dpwYLgqfGzCXnNvmH6uygEBo0dqJNktbtbHt/adU9IT2x
         hF4Q==
X-Forwarded-Encrypted: i=2; AJvYcCXn1cEbbmJ6QUBwFYHE9R4AqjlsY0jHENkeyph5jI552Y2khzgihxtlUUzjwtayxvQ/rUhbgw==@lfdr.de
X-Gm-Message-State: AOJu0Ywahfy2woiTNQmFAX6rljxGjNiBiA6zLgejCh6CFzYvfo9/dboj
	DTzN3lpaOmy04UXLQhlZyuKkjdz7YMe6/c4CA+6xnEJGDMJ6ipUamIw8
X-Google-Smtp-Source: AGHT+IEr1IuvxxUADS+LAME9sSe/zeHBrx1DQfP/gWD3kpUU9B5Qa5Kmr6/7e2AvUxNxKLPxj91J8A==
X-Received: by 2002:a05:6870:b418:b0:393:eccc:b557 with SMTP id 586e51a60fabf-3ecbe585c2fmr12854741fac.37.1764300850365;
        Thu, 27 Nov 2025 19:34:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aPvaZci7DIe2cZ/A7OU1bFAo28ybFvbQo1rRQFBYg9tg=="
Received: by 2002:a05:6870:8101:b0:3d4:d703:74d7 with SMTP id
 586e51a60fabf-3f0d20f0be4ls554635fac.0.-pod-prod-02-us; Thu, 27 Nov 2025
 19:34:09 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVr+X4eYk5MjX5oBnU3Kvld6cC1iOK9tSjidtVG2IPraT3K+05E1T9enPW9i96XWsdlKU+ZD0Iis+k=@googlegroups.com
X-Received: by 2002:a05:6808:14cf:b0:450:b3a:539e with SMTP id 5614622812f47-45112aaceb2mr8720184b6e.28.1764300849450;
        Thu, 27 Nov 2025 19:34:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764300849; cv=none;
        d=google.com; s=arc-20240605;
        b=BouJvKbJbPXqnQae6q0VXOVIdPlrEW3pjvVzzaDr/KS3uYIrDLOL5ntjx1Eq6oRygq
         Lch6uXfo9DxiLp3oNRRWvpfSdwu0LDrIwY+4cR0KSzHiz6yZo1O7flYY3Zmr0QX4y8qI
         MFaTkc+BMiBnPrxPmgTi0La1c+rQ4iSQOruzOgEtWzZs/YUwNaM45t6rIgifT0PP4iUh
         y+3goQEZIp9xKaXv1O1UBvTlbuIqh5tuhAjV/N9i+MpIZB4DizpBohRjho2DwqG/xKl3
         Xw55NgCF8KZImJRn4RuFNSw3pyuRFhfHE6B60WnjOprbyfBUEF4VBP+ZPGkhqSUw2YLI
         FySQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/phgffaeGBCaBWv4I/S2l048MgyIWecznBSacZiKmGw=;
        fh=5SDByJ3Hs0yfOCoQGEuG1sRE6NAvqIWBUeJICelOz9U=;
        b=eNh7tHXkdf0QUVACvasWWMw/EBkUhDs2tdDsKi8p83/dEVE00NB2IhnvcSeaEjsTF0
         cu5htAwUnHQlrlGXl6RG1oTaiLSlc77UCtOrX8f31EfWrCwDgvWr0LitxNEdMImJiuAm
         yf9BrU80NuAuOibUVcoA5z+ZqzSICsw/ccQz6F31wx4HXJy16sQLMzNQ5mW4QdDL7NVK
         DJNLsvOR3mDyhPfZRmWkjZStufSGbl5e/pdpSKXGfdjVGGKAPeCXidYPB8TbvCRjm6VY
         dzvnZ+SDGCxVxe9Gf2RSOPRUJER3P8iCy54JyUo1sftYDr8sIBaSlIZ4QsDGSUOpmCsh
         lDiA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Rf86DUHD;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-4531707bf1asi98706b6e.6.2025.11.27.19.34.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Nov 2025 19:34:09 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-591-g_ehcwKEPAiWXVHUWxLKOg-1; Thu,
 27 Nov 2025 22:34:02 -0500
X-MC-Unique: g_ehcwKEPAiWXVHUWxLKOg-1
X-Mimecast-MFC-AGG-ID: g_ehcwKEPAiWXVHUWxLKOg_1764300840
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id ABDB71956094;
	Fri, 28 Nov 2025 03:34:00 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.7])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 3203D19560B0;
	Fri, 28 Nov 2025 03:33:52 +0000 (UTC)
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
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v4 03/12] mm/kasan/sw_tags: don't initialize kasan if it's disabled
Date: Fri, 28 Nov 2025 11:33:11 +0800
Message-ID: <20251128033320.1349620-4-bhe@redhat.com>
In-Reply-To: <20251128033320.1349620-1-bhe@redhat.com>
References: <20251128033320.1349620-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Rf86DUHD;
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
---
 mm/kasan/sw_tags.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 6c1caec4261a..58edb68efc09 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -40,6 +40,9 @@ void __init kasan_init_sw_tags(void)
 {
 	int cpu;
 
+	if (kasan_arg_disabled)
+		return;
+
 	for_each_possible_cpu(cpu)
 		per_cpu(prng_state, cpu) = (u32)get_cycles();
 
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251128033320.1349620-4-bhe%40redhat.com.
