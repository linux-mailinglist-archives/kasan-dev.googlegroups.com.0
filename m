Return-Path: <kasan-dev+bncBCPILY4NUAFBBMGOUD3QKGQEE4B3U6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id DA0851FA5D8
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 03:58:09 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id k27sf8962563ook.9
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 18:58:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592272688; cv=pass;
        d=google.com; s=arc-20160816;
        b=QRRWNfCkeIBvMXQydDNfOFYfc77ISsnYQNZuTa96tYxFqfLlpxtC5LTqKuZm3nOyMi
         jPANWvi7OLYpC+ft9OXidcNLmCdNQ9Zzk4ovPXNTc52GPOSBWnOKuZ/3ZmxR/FS21M/h
         ovgcsBqTzBfVvb4GCqtV4QcJLRrWIVWRs/ildJ4/8ztviinKaI2q4xw0fYrgBnnTTnhP
         uB7M+3/lzNz9BJd62GDTaF6j8jdt638yEHuToa+5ZS2UFO7CqIYZE9lES8WmvD5oMyGd
         JDdE2ONci+vJQvohxtWAFJnpl7sGStSdN1PkBMb4Kdqxvli3Z8JTovyqEuNjoD0sVPXJ
         BWMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=rjhto8o6xTrlJemCzHF6PcHvgo9W+/w8vpxrbHZIUKo=;
        b=yTq2dmRWg9E1MEPMHgeP/MsGWCebjdLJ4pZKZxoWfvZ5Bp0wUQuFrF1n479M2iI/j5
         +ovLGspiPlBp/T/z53xqHTINGkYpYxrcug+37RCmPG4OR7BosXTzFI1fcahMPZpPd1AO
         S1dnhrcxvzJKW69P2Lst0mSu5kJv9jynQrJeXTuqmtZsum6xl3NWgGELllPYSovNW+E9
         fNXglXFIkg9SjXOyEvg3x9SHOjigJL0Xd6C6yIZP5k3U8tATH61Ia8y/eTveIUL9Z7kS
         etc+M5sZOC1ZkyHCwrNTNiXbd9Bl7/+lHkqxdSTOjNheZFGDY72BueguJdeatfAP7sQp
         NGsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=FrvAOJRx;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.120 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rjhto8o6xTrlJemCzHF6PcHvgo9W+/w8vpxrbHZIUKo=;
        b=q9+Ly1fEuwZDngMuAzL1PemTHcR6Ov8BnavbGZkJb2FLGkFbPZr2twrEQi27a9Qy1t
         OOwNaAlluPd0QGxHevnJoJ0T5qRF55r/4HqXRO8Ln+TKXgIk3EGSwHN7eg7EQpF39w4X
         y6KToko7/9vCHe2vkQtpJZm8+vkmLBH0CyLom2JS6enoH9IAE5lcvpK1DpB33IXZ8Xzz
         9X+mtEjqL0lGGhL+e8/0kFZtMKieYqAWN9CWKvMITj6j8I8R2WCK0pOa5ybRpEP7Urn0
         gvDqCsPSecA4n7eTPcBMb6/qLNHQQfIku3t92Ika/3+pbaDsHXJ4ssPpr3kLd8/ZDUHK
         K//g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rjhto8o6xTrlJemCzHF6PcHvgo9W+/w8vpxrbHZIUKo=;
        b=erOL2iqAgSJR84VxRi1WpXDMpmW4pxDd6wLDU2lRbcgADu2acqCVn9ALKmalOgbzII
         Rjy9Maaxd/L/FaLmzBXkYryK/HYczULlvEFQkiQvPbuDfZZgk1tMuzRx2NgsiPzmXcs9
         QJ9b7YwaIi3BzGuun3XVm2QYVkOwRzWxs+Kj+DdHBO0ouJwxDOZeqZk4Fr9P5/vmv7fE
         vi/eRB4/3tRk5UOAywWVpejqNTC4zHuRV7U0xXmhKq3347Ho+uCGcE6ktrzOMKTm+OEJ
         /pzjr8SVn+R/ugTLNfyiaujlJ1SI47w9fzw+8hAbKaULmsx+To+G34RfI2XSVgeNwD+g
         NrRg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532gOr2tzTzH7kaajLPn8/NEMnJ4rdeZAR0OEs2WqQf6P/FOiZRl
	5GF3B5d4JyHfG2cEC2HSf8I=
X-Google-Smtp-Source: ABdhPJwYowvc950RYzYN/OuICGHvcfnTIOkDtLX+yl6MfYKN6sFV/qQzlg8eLeHLvAr9NvIkzx/Okg==
X-Received: by 2002:aca:4c15:: with SMTP id z21mr1814043oia.85.1592272688427;
        Mon, 15 Jun 2020 18:58:08 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:11ce:: with SMTP id v14ls3502279otq.0.gmail; Mon,
 15 Jun 2020 18:58:08 -0700 (PDT)
X-Received: by 2002:a9d:6a58:: with SMTP id h24mr699815otn.277.1592272688056;
        Mon, 15 Jun 2020 18:58:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592272688; cv=none;
        d=google.com; s=arc-20160816;
        b=sSYGzJ1/iQZhtYBSBj8+p1iyinN6TP8krKuSm4mvD+qfBsAqtlVm4DzPMb32wf5QPw
         WvSnY89GZOB+edASkrNLhenavrp84G5QJBYAvCAvsoZfQh6hjhV+yld1hh/b16qgqPOw
         uXnedQ/fzDPZQau+OnJ2ml7Vg/Z+MkVNYM7duKF/nhkzS70u/Xepw/E4Hca/4NbG4v++
         cj5oaClz/pLH/CbbaxaoDmmnXER1jBFWCfxWXGRxHFxU1PTIZKqRTsZGANGg74Mclmrr
         KPo2P0qC/pfOOSBgApJ2VQmk2C0LazUyYHf5C1J+0BkrlnxS7CuRqVZxX0z2PJ1BrQgb
         E+0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=w0ZJeQQk3EMaWCq5vRe2fLP4T7LhSgQGKZa9FTUZAA4=;
        b=qa+IPMmEDF9UkAAG6wafE6lw8tVDfO5Ot6WaG3Y9w1oe51M7dN+eJw0CWwZ9L8pfe2
         8TE6Hq+AtKUCve5nhvAMx3J1eg5mFejbp5wSWltzRrNkfopdjHmefQFEgMl3RLuCp2by
         JB3/NXGINkdUjAv2XEXhsveEbkgr7BpQgZ8xl1Nibo7lj7kZHfBZVIgRtH5IyvjPVf4y
         hRBlU0Gdw+zvdHM3FkmpzeNpz9/328BzYnYjZqgGwSU1dHRjxGwMCMim/rFvi1kTNoo2
         WOhZ7wlBFhBBE13FYFxXwl7SzhqFTFQ81WTdGpPrJcpB//0gf+pWmyEMDNk8Z0OcT6hO
         5LqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=FrvAOJRx;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.120 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-1.mimecast.com (us-smtp-delivery-1.mimecast.com. [207.211.31.120])
        by gmr-mx.google.com with ESMTPS id o199si803011ooo.0.2020.06.15.18.58.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Jun 2020 18:58:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 207.211.31.120 as permitted sender) client-ip=207.211.31.120;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-271-siDUOdYEMkuGDz0Coifxdg-1; Mon, 15 Jun 2020 21:58:05 -0400
X-MC-Unique: siDUOdYEMkuGDz0Coifxdg-1
Received: from smtp.corp.redhat.com (int-mx05.intmail.prod.int.phx2.redhat.com [10.5.11.15])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 6856710059B7;
	Tue, 16 Jun 2020 01:58:00 +0000 (UTC)
Received: from llong.com (ovpn-117-41.rdu2.redhat.com [10.10.117.41])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 45E126ED96;
	Tue, 16 Jun 2020 01:57:52 +0000 (UTC)
From: Waiman Long <longman@redhat.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	David Howells <dhowells@redhat.com>,
	Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Joe Perches <joe@perches.com>,
	Matthew Wilcox <willy@infradead.org>,
	David Rientjes <rientjes@google.com>
Cc: Michal Hocko <mhocko@suse.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	David Sterba <dsterba@suse.cz>,
	"Jason A . Donenfeld" <Jason@zx2c4.com>,
	linux-mm@kvack.org,
	keyrings@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-crypto@vger.kernel.org,
	linux-pm@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-amlogic@lists.infradead.org,
	linux-mediatek@lists.infradead.org,
	linuxppc-dev@lists.ozlabs.org,
	virtualization@lists.linux-foundation.org,
	netdev@vger.kernel.org,
	linux-ppp@vger.kernel.org,
	wireguard@lists.zx2c4.com,
	linux-wireless@vger.kernel.org,
	devel@driverdev.osuosl.org,
	linux-scsi@vger.kernel.org,
	target-devel@vger.kernel.org,
	linux-btrfs@vger.kernel.org,
	linux-cifs@vger.kernel.org,
	linux-fscrypt@vger.kernel.org,
	ecryptfs@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-bluetooth@vger.kernel.org,
	linux-wpan@vger.kernel.org,
	linux-sctp@vger.kernel.org,
	linux-nfs@vger.kernel.org,
	tipc-discussion@lists.sourceforge.net,
	linux-security-module@vger.kernel.org,
	linux-integrity@vger.kernel.org,
	Waiman Long <longman@redhat.com>,
	stable@vger.kernel.org
Subject: [PATCH v4 1/3] mm/slab: Use memzero_explicit() in kzfree()
Date: Mon, 15 Jun 2020 21:57:16 -0400
Message-Id: <20200616015718.7812-2-longman@redhat.com>
In-Reply-To: <20200616015718.7812-1-longman@redhat.com>
References: <20200616015718.7812-1-longman@redhat.com>
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.15
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=FrvAOJRx;
       spf=pass (google.com: domain of longman@redhat.com designates
 207.211.31.120 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

The kzfree() function is normally used to clear some sensitive
information, like encryption keys, in the buffer before freeing it back
to the pool. Memset() is currently used for the buffer clearing. However,
it is entirely possible that the compiler may choose to optimize away the
memory clearing especially if LTO is being used. To make sure that this
optimization will not happen, memzero_explicit(), which is introduced
in v3.18, is now used in kzfree() to do the clearing.

Fixes: 3ef0e5ba4673 ("slab: introduce kzfree()")
Cc: stable@vger.kernel.org
Signed-off-by: Waiman Long <longman@redhat.com>
---
 mm/slab_common.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/slab_common.c b/mm/slab_common.c
index 9e72ba224175..37d48a56431d 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1726,7 +1726,7 @@ void kzfree(const void *p)
 	if (unlikely(ZERO_OR_NULL_PTR(mem)))
 		return;
 	ks = ksize(mem);
-	memset(mem, 0, ks);
+	memzero_explicit(mem, ks);
 	kfree(mem);
 }
 EXPORT_SYMBOL(kzfree);
-- 
2.18.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200616015718.7812-2-longman%40redhat.com.
