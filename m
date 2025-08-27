Return-Path: <kasan-dev+bncBC32535MUICBBIMCX3CQMGQEDO3FMYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 95AE8B38C4A
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:05:23 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-327709e00c1sf283794a91.3
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:05:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332322; cv=pass;
        d=google.com; s=arc-20240605;
        b=fITiYQV5VWn4qXbbQfPo72hZVtUFiG93dKihfob/kh0imS47hASAtd2gLq4mc/DO/E
         TViK1n62jJcXH4DwfeVvwjJ1bIGRqxzSZ2U2UNdseY6qRuvB9OW4lIo7HQtedRFznIXU
         4tWvvEL+DuWXbz/Jh0O63HBDADvs7e/jD/u2j9TVA/y5qXOx70HoaXEWmWHuplrKVrLf
         d6WWd6TevhAbvLg68NdkfIJfCIoQ6jlb4r4qtGoePQ7Cm3ZJZqLN/RdWsGTnnhQm5pG2
         ySjexkPWxWmuFKPlGJeiyIVG0FW0sA0oDaR5Ap9wwEN8vOQ3qayT4iil7rddS5rIxYN7
         vc4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=4QnBuAZsTUs5+wE/Q+I0OCS3SoHezcB+fs8aA4zCKh0=;
        fh=yPO2BARMJNRi7vU7ZAqM+FP9Ea+AjE51tH0DE6djqg8=;
        b=f2evqKxxMQBo+mdgv/e+q263/H4zLFnBUTSC0qS0lJguHfZVXeITRRf1JWpHbvXfUN
         FUsocmckDkSXcIFTALk3oUq08wshJO2zz4htTDN5t/iveXR7EtrGWOtKgngwSnMtjcod
         hcWq7cibbQyRsi1E3wljntqMjyXvGRTdPhmFN2iNayn/Cx5JK/LMtA3kCSCax2bv8PIP
         xpv8Aw54+2v71inHL3fEA1pvJWoR9rtTZAjiG7FCJ/j2iIZ5ogwAaEYN8VQpAN6nH385
         ltwILhKzs2vciWXh3euSLwsZ6jLJqZplW/Jinn45t6QiFXHcAgVTwlEafwC9yJ1f6A0i
         HV0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Vflmn91o;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332322; x=1756937122; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=4QnBuAZsTUs5+wE/Q+I0OCS3SoHezcB+fs8aA4zCKh0=;
        b=wqVlnAeMgjlodzTFFRbtbsMIh9Y9zYI3z3NRkLpWleKplFUk1AdzSafIEdWCUIBP8u
         AkXJLolg6Z43v+YCiaBIcP6ov1UsEH0+q3tnbVzBulaKJNL8fH/lccnMbeskeUMs71AD
         1n7dXRrwb7WX471xGb9XzIn4rAXogvzrRk7s4I7uOZVnC1o3MzQLru/JJq+RS7Fk7I0r
         mZL9C6aubWcXBcIxNMWVR6ueSQFwO3sRCTDzdFKMTCyJSvc7F6ZHGbT5fF/Z9gB/YSgA
         JQZZHvOGuW3VDMHK181dTfmtZETG7Hfsu5CvU1oKYV4hoZajaWsKLeGYhQPTCJk8GGVX
         VEnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332322; x=1756937122;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4QnBuAZsTUs5+wE/Q+I0OCS3SoHezcB+fs8aA4zCKh0=;
        b=I9d/m57YXhnOYp1V68uO4+Un1pfNU+z0QGRuDHp0RpXwFYgOCO0wxAL4165yMPHha9
         xtNzTLWhJJr90xPV+Lfgy6LlxgA9kEKNSSw/l3Z6nCGjUjSbCpnZ1M8spwqhnhqUadzF
         a4BdmMCWAfBfAjKPOamyY/vkSbFqluw/HFjItN155wL8CBIyQ5seeuegscGwVKJ55wsQ
         iBNIFazwxbPbgU15bNmOABAYR6HH41HtIoOO1GveKrH3Hrv8N0BO0RhowCrT/bG22xnr
         mPhIz6+D0gdNVba+y/lIq6/ec3T5SL4TPOq7k1nX6a8mA96ybpbMt3ZWT/0wp8/4pTaa
         9o9Q==
X-Forwarded-Encrypted: i=2; AJvYcCVUF36VH+HAH1WIPY//O5ADwaZI4tCOogKjDKXN7xB3iVuZhB8ebPfUbXpwSxfJynOyWMphsg==@lfdr.de
X-Gm-Message-State: AOJu0YxzEo/PWtMzegBrXBa3GNFZQ7KK2Rp670aHOFqXRLB8kV+9m4Z0
	JqfpavT6g8oLA2oRnspMCEvwOZyOPECgg5xvF0O0kjiVLt+/SKJp0vy/
X-Google-Smtp-Source: AGHT+IH2v/An3goH+y8+j51ksjPIeCRWjQIyWloe9aXwBFPVhzclCrDWYANrrssydBFJCxfzzB5jlw==
X-Received: by 2002:a17:90b:4c48:b0:327:734a:ae7a with SMTP id 98e67ed59e1d1-327734ab03amr4006991a91.11.1756332321964;
        Wed, 27 Aug 2025 15:05:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZevTV6wGWlq0sLrhM/u5rocMuioYcSGRO9JVR5HCw2BvA==
Received: by 2002:a17:90b:5082:b0:325:7c02:d093 with SMTP id
 98e67ed59e1d1-327aac6d100ls140133a91.1.-pod-prod-04-us; Wed, 27 Aug 2025
 15:05:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUPIhSZdmhk27CXRMAPNl8Fr0J3sp2q3oUe1+JEQyc2Ie05ElKXOahO1tdHaWoLnzONpzaa+1BxUtQ=@googlegroups.com
X-Received: by 2002:a17:90b:53c8:b0:323:7e82:fcd with SMTP id 98e67ed59e1d1-32517b2bba5mr29109555a91.37.1756332320633;
        Wed, 27 Aug 2025 15:05:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332320; cv=none;
        d=google.com; s=arc-20240605;
        b=eI1mmYZaIfNX+19irHLBX/dsvLxqLoh35i9a3U+4FKGAJJshGKBtPafRHnOhR3+Xxj
         uKcEXv9AETqn84/jbjUqZCGqIkCqI7FfVEyCfb/9NoscAruBb2y8cn94AwAbeZSxIMVu
         yt7SDexWzTdWke2cMNG5cOV1mCNdku7FyWu2N+3XlkofAeyjP6VsPg66eapWpltN8pOW
         LPNMULkAwESmcra0TLXrJ0nbtW7YHyArOBZL6NxBoZWQ2ckqYBMPOclHGKxyNqmlIPA7
         AuYVFJJZ81IwH0CX9tJNf2IBramk/gnR3oWE9Hx2ptKFSFgm4nUejbk1j+/J6irU7Tuu
         qEpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=D/EwzdzyNFR+ewVEEFqEze2ovwyb82bK+Rce3/V3U0s=;
        fh=BCe2j8uw4cDMMzBBisW+kIEepM9ekfrlw/UgVNc9CbM=;
        b=FDkaAZvqt8X9UK/iNAM3zt06Ah8vZtW3lqQVfYZAeXolH9OPM9bOH7Vj3PQBQRKdfK
         Psh09YiQLa/K0IVYBN/LOzWpaH9e91pa0IM0seeCxzgsuiaz6zJ2lEeIFgFHsgvtL9Ij
         bLz8NcPwWf44akfgiQvJScHYsFPY/PDph69yD58C/chF/D/50eerEv12XQDg1UCIpabg
         1YUV/bjO9t8XvEvJyLU0HCBp72Yx15m6DueJn8hCgXwj30wYg5halwJ0QFOm2YoOHVDy
         Eat7PCPgH6aGzGmIYpgBy+oLLTBxbgec355w9Ruka4tzYDFgfwHrS/mb/QkWWpHEo0cD
         c6tw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Vflmn91o;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-327914df480si46288a91.1.2025.08.27.15.05.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:05:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-319-rAeDOcrbOYu2jFZVlj4BxA-1; Wed,
 27 Aug 2025 18:05:15 -0400
X-MC-Unique: rAeDOcrbOYu2jFZVlj4BxA-1
X-Mimecast-MFC-AGG-ID: rAeDOcrbOYu2jFZVlj4BxA_1756332310
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id E3F20180028D;
	Wed, 27 Aug 2025 22:05:09 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id CB62530001A1;
	Wed, 27 Aug 2025 22:04:53 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Zi Yan <ziy@nvidia.com>,
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
	x86@kernel.org
Subject: [PATCH v1 10/36] mm: sanity-check maximum folio size in folio_set_order()
Date: Thu, 28 Aug 2025 00:01:14 +0200
Message-ID: <20250827220141.262669-11-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Vflmn91o;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

Let's sanity-check in folio_set_order() whether we would be trying to
create a folio with an order that would make it exceed MAX_FOLIO_ORDER.

This will enable the check whenever a folio/compound page is initialized
through prepare_compound_head() / prepare_compound_page().

Reviewed-by: Zi Yan <ziy@nvidia.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/internal.h | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/internal.h b/mm/internal.h
index 45da9ff5694f6..9b0129531d004 100644
--- a/mm/internal.h
+++ b/mm/internal.h
@@ -755,6 +755,7 @@ static inline void folio_set_order(struct folio *folio, unsigned int order)
 {
 	if (WARN_ON_ONCE(!order || !folio_test_large(folio)))
 		return;
+	VM_WARN_ON_ONCE(order > MAX_FOLIO_ORDER);
 
 	folio->_flags_1 = (folio->_flags_1 & ~0xffUL) | order;
 #ifdef NR_PAGES_IN_LARGE_FOLIO
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-11-david%40redhat.com.
