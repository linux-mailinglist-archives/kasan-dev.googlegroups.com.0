Return-Path: <kasan-dev+bncBCPILY4NUAFBBRWOUD3QKGQEVOP67MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id A63001FA5F2
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 03:58:31 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id j131sf9917378oib.3
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 18:58:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592272710; cv=pass;
        d=google.com; s=arc-20160816;
        b=esLI13e0pWVjq5bsRLX38tAcvWRxdSdD122uZ2N3BOdmA2nRKRSzqNtm0xBOxSa7U2
         sPlCJt0BOvj9JZTTSdnAz7wFdNL8kErqQGH2xN5BJOl/x1joLXTc2ldyUf2dgfILjb7e
         6CP8sl/8ZF9kcTxSfGrfHkj7UeVMkw3YjIkAl7fOhT0e0DMw7MYZh8LGnm6a7zrtWP/m
         VhxHsIY2BzdpR0iUm+Tu/25zgfcErvP17b13KlUnsDJcx8D4UorXKB99iU8x0bN+7e14
         8xHh7/9+Um9G3o56IcbJEquNgHwtz/LMOy2wqBGfLBxYUBV0r3WTXZikQQq8oO1VcoXv
         y+Ag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=NiXrqv3AhfN4AcQ9qsvpItMi0G4Cfb8TmSUa4emUXWw=;
        b=FcorP/Nxl1bEZsKx5i7gbgCRtzgD257skX3SznXpoT+qajOsJ7IGaEpgOA+rglG/8X
         AgD2uAE7Nh/3gqmI03/6kJj/KOMn0r38CJpPHX3D+GCG07gNwnz4i/buOqFPc8JCbWWl
         8WDTHK42t627K9+TTJIZHmhrA/RsUASUQ5EDF2+SDvZJ41L9yVSMRYy/pfpcVIskK0OI
         bMUSgh75XrgyLjlK+BDy4Fm2MZMMg+OkDe2pRj5fq9PUfPQuMPmboZ26RZZ0Wvfg0pgA
         Z/4k5seu/HVyFN3ilTpPMnmeJd9FED67aG7dzLUiZitZkQVI/uHMOscZPZIJZGWExKDT
         5zDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=R5yH8nde;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.120 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NiXrqv3AhfN4AcQ9qsvpItMi0G4Cfb8TmSUa4emUXWw=;
        b=HBXbpK5ODha6eq8gHfk0DgltXtkyE+e9j0egO32y9XrRHbsFCkWoVRpG55PuslCKrn
         h7jLOjK/+rPhqD9LpUouqhK7u4nMcZcKzisFRuOJRyi/TE2c1GvLz4UBY+zj7znNc5tt
         CsiAk9qc0Yw6gCzy0tmKD4JHWqIChhMvTEafIpLIuJsNrJgzkaFf4GIS8eBInrVdxfLY
         V44mIW3gcv0MnjXYdySlAj6x+PxYVBAUG3TxNhFGgi5qlFzmj8V8A1qRcarO8RkrZuss
         j8trAioYMBYOV89W25SgsaGRJqy8hCb4jVw414XpGFfSjqRpVxBGJuOnwL03ESCfDgCH
         bQhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NiXrqv3AhfN4AcQ9qsvpItMi0G4Cfb8TmSUa4emUXWw=;
        b=FPTLPjErtBFG+VVhIaeD+AYdLXEavWLRX9257nWB8i9skTFThTN4JV5M/oNJj0tPBo
         rFGoI0MoGPhhw7C1hVH42FybE6fL4kE6lvkZBv/n+rx0OvKideatR3i8YrXgnudNNKqF
         chJ7ICapyh00dl/MIEHuoJ/Kj3c8QbA6ztcmg5F606H5xKJ/8wtDdBXR/DQN1R7WPEbE
         7D+/+a/8b6L+FITXnXaiIuUiSJqS3dxCzvsUHErzKOHWpjmybWW4QQ1qXE0mvl1NlWd2
         jcCgoERS4RNJugdSAYfRP9rVW1mTXDmchtGX55MFmVh4lOtffvphAKgXPIGVQRhXKwd3
         JGoQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530K6BcU3fUQBc6+bqaHBrPPiSRe0ZvvjDGn+Gy9QO+Ct1sf12Gl
	40IJoHyYiFFvxrLxA4x+HuA=
X-Google-Smtp-Source: ABdhPJx/yhwji3XUgnJS3HBEWAWRuT8V6lwZCL9GccBK/ss+azzC0c6chaEWQYbYY2l/RFNqk1zxbQ==
X-Received: by 2002:a05:6830:12c1:: with SMTP id a1mr693897otq.123.1592272710644;
        Mon, 15 Jun 2020 18:58:30 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2116:: with SMTP id i22ls3507692otc.1.gmail; Mon,
 15 Jun 2020 18:58:30 -0700 (PDT)
X-Received: by 2002:a9d:4716:: with SMTP id a22mr713265otf.341.1592272710344;
        Mon, 15 Jun 2020 18:58:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592272710; cv=none;
        d=google.com; s=arc-20160816;
        b=z4bA1ChIAeV8d+/8icM9v7+d6ZyOIh5FKyHQSXC6ut7f98gmzmFfVvqApQZ0rcUKE+
         WEIs1NIwHHQpjhIvW0d8j4qT/33DTXf95zJdFuMgVU7YglhlymZd7H1QjHfTO6/bHswM
         zj0gEwQ4Rlmtjf4nB2NcG6Szqz6MtVLcx2PtbnvcKYTUxkAxvMbab80dIEdSOHMGO5nT
         vc6tOBjBhgLH3Pqak7KJzCmlKiJRMOG54SbNko+Za67kvcrnaPFHIuK4Fg2NdMl+EXWx
         hVBDNhrcOBxDv3PbgZXr2N7vycnnybGdz56hWh3M+XUAL9v++MVVbo6OArC7ppuMvg+p
         i1Mw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=zNT9QNZqNhCOtvB39Ne/de/mYb4LuwliJqmp3BjLDNM=;
        b=GpsJLXT+P1QdLx6DUFxrZ8PvC0+cseGiFnH3LBkoMG7X8MFPYZPyQQ2jCqayqZwPpd
         bflSBLRjcvLiulz+hBUJqZHmnz/3LJvhbui5A61M1VCuJy3oAmzDIZQOzRnkIVWfjyJk
         lyebyn0QxHNTEOoc2YwSZMkct7n+7YVjmllM0NtGtr02JMXz+6Q0cfXmHsB/B3loK6qV
         nivoOjz+JS7iajRFHWjLM909W1fgzBBhTn6XDZWhgej95bcG0ADdSdCLRsLNz+cCTYsd
         Fxs/soLud6ArcZY6zIOa5Za0FGiwKGXlx/WVxbJbtCFfNW2l5RbR0SDpsjFp+669NgHt
         ZXzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=R5yH8nde;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.120 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-1.mimecast.com (us-smtp-delivery-1.mimecast.com. [207.211.31.120])
        by gmr-mx.google.com with ESMTPS id z6si605671oid.4.2020.06.15.18.58.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Jun 2020 18:58:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 207.211.31.120 as permitted sender) client-ip=207.211.31.120;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-275-En0zXgVSO2KfRECG05UTtA-1; Mon, 15 Jun 2020 21:58:20 -0400
X-MC-Unique: En0zXgVSO2KfRECG05UTtA-1
Received: from smtp.corp.redhat.com (int-mx05.intmail.prod.int.phx2.redhat.com [10.5.11.15])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 55EBE8035CF;
	Tue, 16 Jun 2020 01:58:15 +0000 (UTC)
Received: from llong.com (ovpn-117-41.rdu2.redhat.com [10.10.117.41])
	by smtp.corp.redhat.com (Postfix) with ESMTP id B4E4F6ED96;
	Tue, 16 Jun 2020 01:58:10 +0000 (UTC)
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
	Waiman Long <longman@redhat.com>
Subject: [PATCH v4 3/3] btrfs: Use kfree() in btrfs_ioctl_get_subvol_info()
Date: Mon, 15 Jun 2020 21:57:18 -0400
Message-Id: <20200616015718.7812-4-longman@redhat.com>
In-Reply-To: <20200616015718.7812-1-longman@redhat.com>
References: <20200616015718.7812-1-longman@redhat.com>
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.15
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=R5yH8nde;
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

In btrfs_ioctl_get_subvol_info(), there is a classic case where kzalloc()
was incorrectly paired with kzfree(). According to David Sterba, there
isn't any sensitive information in the subvol_info that needs to be
cleared before freeing. So kfree_sensitive() isn't really needed,
use kfree() instead.

Reported-by: David Sterba <dsterba@suse.cz>
Signed-off-by: Waiman Long <longman@redhat.com>
---
 fs/btrfs/ioctl.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/fs/btrfs/ioctl.c b/fs/btrfs/ioctl.c
index f1dd9e4271e9..e8f7c5f00894 100644
--- a/fs/btrfs/ioctl.c
+++ b/fs/btrfs/ioctl.c
@@ -2692,7 +2692,7 @@ static int btrfs_ioctl_get_subvol_info(struct file *file, void __user *argp)
 	btrfs_put_root(root);
 out_free:
 	btrfs_free_path(path);
-	kfree_sensitive(subvol_info);
+	kfree(subvol_info);
 	return ret;
 }
 
-- 
2.18.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200616015718.7812-4-longman%40redhat.com.
