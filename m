Return-Path: <kasan-dev+bncBC32535MUICBBOEEX3CQMGQEXEICS2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id B3C2AB38CE3
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:10:01 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-61bffa86761sf323814eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:10:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332600; cv=pass;
        d=google.com; s=arc-20240605;
        b=XTTrgMqA2N48Q9+m5whzL9NCHU4u5qajevsPWj4Cdz4d8eMRXCLQc3/3W4zmP6L0vz
         MEB41G6XsU5tHo1Ul9jKbeLat7NorrhekhWig7QoMomQ7ELsTW0XPU4Bl3QE4pzZzQfd
         JT9+nESnfNCtL9Q+yd6bJ9q3koE6TbsjG7TIsYOe4VYXd6fYL74bbegyodrAW6hb5jp+
         v9lZQmn+rql5Ss8E+fg2xltYvpLRgHSAhoB1kKfiSiZcW4M+KMp3SwcaDacTS1kLrrWr
         xFzWuEJIaXFuBbM01hTGBZs18TYbHX4oWR5wP98a6Yz0HxgwUoj4uUE7dU3MpVncPnF6
         v8TQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=+mkVIPZsYA0L20Jam7kYc9ALpxvuxKDWEV8jO6i9eaw=;
        fh=jRhG/iBLho6CdKAyR9qZsbra5fraDbc4AqJqyz3gSys=;
        b=B3CAmjUfVy/fuDVqpwoaQiFHYT+h4Wa5/w+Kuyq7Vl2SVdhz46zJNG1wvKuJTCMg6h
         O/J5EZaQ73GS/+bjcmYvtgGLhHqHjjGNgJX4ZOdMiL1S4UHIl8rDfhrYiMF2lEAl7KgJ
         vQxvNkXt5IYjZ0fm38Ovzw4W6by2IL5FbOyfEAxFclmjFJ2ZLlbTncq6Jd7EDRFYjD1o
         5Okbe8qqf64FtxLWEexe4sKwPwFcjp5XPFlQSTvdr7/5eoefEI1ncARTb8lcOWVWCbQB
         l+aS1x9geFO0NpZDZHH/Tlf2Rv+fq7GQ/NYsH+BdQVNSHOnv73SG8CGgVbLR/rgvpPXZ
         AEoA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=dDStDSiu;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332600; x=1756937400; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+mkVIPZsYA0L20Jam7kYc9ALpxvuxKDWEV8jO6i9eaw=;
        b=LvG+Fuv1hTf8fLAzXcn7Xz47K17HfCAW0NNlAKhmP+SvxdLNcLxw/6LswdtZpvqmWS
         Mb6zaej7f4gJBHR8fNJ7SNB9Q02eJfLMgWzKSdlge4Oe123RXPlxkVe8d0VmnhVcsZHa
         d9L3k6L/20ogKWTzL/S0vamtPjpiHqAFpOC9JNkt1WwTpVhhXVIEzf+GeoO6qW/JwfXx
         cvunFVHFC3TGkPiLJ9IsH3slmlsZ81s+xdl8Szawolj8HFDplqAK8AyWsARvU42kThRM
         8aBy/wW4C65/0CUT313R0Fv7fVJwRAj81Fvl674u3xNkEIShBGvzsFtKOlowE1k8RYBE
         dTAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332600; x=1756937400;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+mkVIPZsYA0L20Jam7kYc9ALpxvuxKDWEV8jO6i9eaw=;
        b=oNVUvkj1OSUAU6LPCp9AXKlVlFn+wciOnMd3zlIOPKpPlvxG3I2We+s981fiRgSQs8
         72XNudm6OSqr28Uv6KsT72ELXXPZnHfC0kEt5ZbKGUc+PTcg57juR4NVJ9FPB1Vax70i
         yWIeNSTKZkA/2L8zCqhgCa9YL/tYt37mBmlKc4zbr10SJTHtt13O8w0HsrwNHIkK4v+m
         E4DG5Vyesn8hkYBXIJCuqab5aZGbCgbXZpdvayVgUBFiRVuV8QJKYFbdalAcHeYhmPQE
         xMoqnPBJwhXM+DyhqovpAU5/8wqt9wxEyFHq0zRsgfFo2g5Y5xEwOqgmkTxiJ32YPQP5
         /tEg==
X-Forwarded-Encrypted: i=2; AJvYcCW+6RPIvZqmg2G/2lhXg2m9z21mhBgQblh+jFQU1LG7hSLa0u651J7vSJ5EaKW6yXW0Yaya8g==@lfdr.de
X-Gm-Message-State: AOJu0Yy6CSI4EVZPm5pzzB88nUFZCMb20sYVA0Z6MsKmg2KgWZy5FsYg
	LX+JKDaCmK28t6gP5ebuIGT2gmD0cZSsNkPkc6Bef6ogfCMR7pBg1TCw
X-Google-Smtp-Source: AGHT+IHREHIfNpD7OAUeeHsuVr/OXhjWmrfZN5ZjpTE7noFqJxJodYQdH83D0c1JmJ8lHEQ3WJ37bQ==
X-Received: by 2002:a05:6820:1caa:b0:619:844f:2d0e with SMTP id 006d021491bc7-61db9beeb19mr9223241eaf.8.1756332600227;
        Wed, 27 Aug 2025 15:10:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe9DEPgFrsCPKfkYJh0eWdTdUPFU7FYGFWRKyW5lfxG/Q==
Received: by 2002:a05:6820:6789:b0:61b:fb56:5dcb with SMTP id
 006d021491bc7-61e127e6ae9ls20875eaf.2.-pod-prod-03-us; Wed, 27 Aug 2025
 15:09:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUATnJcCiAMVCEZ2HkuJZmJX+kvs/1oA1Y6vb6Cx334eSi5xQMg93aW5gze8olUzI/EyAAejtH5K28=@googlegroups.com
X-Received: by 2002:a05:6820:1506:b0:61e:a21:95d with SMTP id 006d021491bc7-61e0a210a56mr1400462eaf.0.1756332599431;
        Wed, 27 Aug 2025 15:09:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332599; cv=none;
        d=google.com; s=arc-20240605;
        b=ZYw+VKuGLtYdTodsAFroaH7srjN1G8Lg4WjMonP7Kb3S/YbiK5sfeyzKUdINh2Bt4o
         HHKeqxLwsemRYrEnaMM0lCYdRxALcAgpmpCC16ghm40PJAuiZ/7qN0wtAAqgHZ7O5qIF
         7wlk8TNDKjlVw5rRnuALeT8wmuxvrQ09JO4a2Py15OTZK2n0nFPbAeD5UUCqN4hy2irc
         MvTCVZnFVAgB+Ocp8QYURpN4YVqtESVYhan072OYyOWD90Oa9VNwJLIe3cOhHkOewtLg
         ycvC2gSw3KkBtJ38uJS1rdSUhZTFEFHY83Su2YFzqCeX8vjh3ZAK8q09GhnBb7sAzfOK
         3KyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=GXg5sKb3LQ8Ovlzb+xXgvQsFzOeAfDPZ/pDh6HDj700=;
        fh=kwQeefftB7j9Uk4cNGb0Fa04HMqO3NJhkl6Z01LSZLY=;
        b=gah0kLe0Phap1z/1gZBsmdyswWa3tYeVj8DCp14QpUohyyZNIHRH+ofUaBG1rRGxR/
         tRZ4Pa6611R4QF5J9B4XxytMt/w5am+7G88HVdIcS+jjtyVXapOkt33DAJG16KOtX4Sf
         x7RbBUEnq6uw8/3OYZqw7bSOrDeT8qpUV64wG+14nlwQ4dF/6qkbt1SW9JvNll7QpYl0
         70TvYMcwjVERxUZjwUNeVy7wJdS5N8MBdUUUrQsKog1EZyWfj5ZnG2yviR8xZzrSVRPy
         ESmCBwh9KmQfQkknRAsiKAr2NPwMYVNTlRqoevMgomW56VvZZjPkKfxB2DIzpFnPEhqa
         5Z2w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=dDStDSiu;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-61dc76f082dsi525647eaf.1.2025.08.27.15.09.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:09:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-474-6glRl4KNPgiaFeNg7_zkYg-1; Wed,
 27 Aug 2025 18:09:55 -0400
X-MC-Unique: 6glRl4KNPgiaFeNg7_zkYg-1
X-Mimecast-MFC-AGG-ID: 6glRl4KNPgiaFeNg7_zkYg_1756332590
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id F370918002C4;
	Wed, 27 Aug 2025 22:09:49 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 9186830001A1;
	Wed, 27 Aug 2025 22:09:33 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Maxim Levitsky <maximlevitsky@gmail.com>,
	Alex Dubov <oakad@yahoo.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Brendan Jackman <jackmanb@google.com>,
	Christoph Lameter <cl@gentwo.org>,
	Dennis Zhou <dennis@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org,
	iommu@lists.linux.dev,
	io-uring@vger.kernel.org,
	Jason Gunthorpe <jgg@nvidia.com>,
	Jens Axboe <axboe@kernel.dk>,
	Johannes Weiner <hannes@cmpxchg.org>,
	John Hubbard <jhubbard@nvidia.com>,
	kasan-dev@googlegroups.com,
	kvm@vger.kernel.org,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	linux-arm-kernel@axis.com,
	linux-arm-kernel@lists.infradead.org,
	linux-crypto@vger.kernel.org,
	linux-ide@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	linux-mips@vger.kernel.org,
	linux-mmc@vger.kernel.org,
	linux-mm@kvack.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-scsi@vger.kernel.org,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Marco Elver <elver@google.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Michal Hocko <mhocko@suse.com>,
	Mike Rapoport <rppt@kernel.org>,
	Muchun Song <muchun.song@linux.dev>,
	netdev@vger.kernel.org,
	Oscar Salvador <osalvador@suse.de>,
	Peter Xu <peterx@redhat.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>,
	Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev,
	Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com,
	x86@kernel.org,
	Zi Yan <ziy@nvidia.com>
Subject: [PATCH v1 27/36] memstick: drop nth_page() usage within SG entry
Date: Thu, 28 Aug 2025 00:01:31 +0200
Message-ID: <20250827220141.262669-28-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=dDStDSiu;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
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

It's no longer required to use nth_page() when iterating pages within a
single SG entry, so let's drop the nth_page() usage.

Acked-by: Ulf Hansson <ulf.hansson@linaro.org>
Cc: Maxim Levitsky <maximlevitsky@gmail.com>
Cc: Alex Dubov <oakad@yahoo.com>
Cc: Ulf Hansson <ulf.hansson@linaro.org>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 drivers/memstick/host/jmb38x_ms.c | 3 +--
 drivers/memstick/host/tifm_ms.c   | 3 +--
 2 files changed, 2 insertions(+), 4 deletions(-)

diff --git a/drivers/memstick/host/jmb38x_ms.c b/drivers/memstick/host/jmb38x_ms.c
index cddddb3a5a27f..79e66e30417c1 100644
--- a/drivers/memstick/host/jmb38x_ms.c
+++ b/drivers/memstick/host/jmb38x_ms.c
@@ -317,8 +317,7 @@ static int jmb38x_ms_transfer_data(struct jmb38x_ms_host *host)
 		unsigned int p_off;
 
 		if (host->req->long_data) {
-			pg = nth_page(sg_page(&host->req->sg),
-				      off >> PAGE_SHIFT);
+			pg = sg_page(&host->req->sg) + (off >> PAGE_SHIFT);
 			p_off = offset_in_page(off);
 			p_cnt = PAGE_SIZE - p_off;
 			p_cnt = min(p_cnt, length);
diff --git a/drivers/memstick/host/tifm_ms.c b/drivers/memstick/host/tifm_ms.c
index db7f3a088fb09..0b6a90661eee5 100644
--- a/drivers/memstick/host/tifm_ms.c
+++ b/drivers/memstick/host/tifm_ms.c
@@ -201,8 +201,7 @@ static unsigned int tifm_ms_transfer_data(struct tifm_ms *host)
 		unsigned int p_off;
 
 		if (host->req->long_data) {
-			pg = nth_page(sg_page(&host->req->sg),
-				      off >> PAGE_SHIFT);
+			pg = sg_page(&host->req->sg) + (off >> PAGE_SHIFT);
 			p_off = offset_in_page(off);
 			p_cnt = PAGE_SIZE - p_off;
 			p_cnt = min(p_cnt, length);
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-28-david%40redhat.com.
