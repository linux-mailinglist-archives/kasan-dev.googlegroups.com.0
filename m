Return-Path: <kasan-dev+bncBCIJL6NQQ4CRBMVXUP3QKGQEL4EVBJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 370E01FB4DB
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 16:48:19 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id y133sf213080lff.20
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 07:48:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592318898; cv=pass;
        d=google.com; s=arc-20160816;
        b=Oxht9pyRb2Sa3KXG2s4nlDWt+DkFqvsVojZtd2E4F+w8dGy12ElXbuV2PhR61PEY7w
         qhQnnn/gIHJYk4lV1oyZATBFNlIEGK6yVfFvdt2O7xDrfPOz1ZJKCndWo+F0YiZm0tqc
         +cwxXOwGQYpbeZ6BIPqZaENYuUI78gyjQ0jqxQD9MtNpUl2XhTFkJfPIFLlfrrpIygRO
         lW41DUyy/Nx9hTDGhhapN66ozBtQQTxoZZw6AXOvyZkhy1b4PteZA7tKOksmXIkR7ShZ
         0KxDrzuQzFDRiTZEOMrSgbMJqTAosLibBu/H7meMDxDNZfcW2qBStTTF0055mReDiKzl
         VnXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:mail-followup-to
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=it2AimjyLusrPGYMqIf2kWtxnLq296cjLXdiHClwnPA=;
        b=Ll1FmmJWyeuxbaYlkNX5OarBn1r9D1AGB+gzyBW+km5sXx91XU5zA88aXlx7YsS8D0
         KQSmBRoR/qa7HtnuS6m0hUmAnzuv0Nb/yNI4A+9MC/RTu6btKeZF51BqvMUACLAFJOLg
         AOgkZmHcL++sqlJ1IhOc3zGCxwvO/3GSCGfq57FeQn839VLBdGee7CtkOPSIgjC7Pqj0
         dR5vmHmqJRim1/Z7csHPGt9fX20bOpZY6fWLNqiF2/thDzE928zechRFDCmjwZ4qZkx2
         w2evwgexXMFdCIPRUYyPUiPvWL9X+huHVJB7oBy/eF7YYjzuUaKOUn5SkNkAxEPahtb+
         h3og==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dsterba@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=dsterba@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:mail-followup-to
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=it2AimjyLusrPGYMqIf2kWtxnLq296cjLXdiHClwnPA=;
        b=WPipZ5uKK2LXPd4BxQlaoZ4qt6AHOpWjKgI7Hh3PvlPjLjxSvQB7oogmI1vrbatTaR
         AUgK5yjxmmIfAf9O9xdA6I152Xwjbcau7Gt76Ym7pih4eerGEF3FxjYahRWuaB34NKQK
         CHvy+xJJlWz1g+2mKDo3z3jRaEmC57L9agELxvGyYLekJxbeLWIre9h672XxeIdbt9HY
         /z0VzdbHoAFck6/VhftnId+UheuwFrLXLjYAH8xrO/jkzFilWYKshXyXfNSndH2S5Ad3
         V/QIK89KBufCPJJSrElCnVMIcxS/py/aPpbLTfPvbEG2ugWZTZGD4kc5oQdI/x7a9MaS
         Ae8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:mail-followup-to:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=it2AimjyLusrPGYMqIf2kWtxnLq296cjLXdiHClwnPA=;
        b=d9XG6U0+EwcdkO45AaBeuTwt1q5R5Dlk8MCyo0eiv+wmmM8RpKT1UxHu6iuJWJ/iOP
         /stToAYQ4XkAtlLq+h15SRVMbR3vM3/0+Q2NZ+WR1m4MS1KJaCFD1L5vWpYZZNj0aQ6r
         Oj9eBPQWGR85nDq4ZC1bnDxbCayqjShIBoy09p8wjg/Whex9iSwxNaOsCjqBrpFCd81B
         4Doj7ojl4A3RdHTAsnW1Zdn+D5eQXMCfvUyzVPgpJVb+mNKAf49bhx5eU7L43Umuj/V2
         RkAZQ3P8j9fUpWYPLJjDN8IY/npMdvShKW2almJHU6Z+OOHwfC1y+fs/QGeircrb15NS
         XeWg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533xUw6Vng/C4KUqKUo9QUlK7bRmc5d/5Tp9bHvqRsAOxFt6C70u
	1Y0B2HVS3RL9KAWXmz+fViM=
X-Google-Smtp-Source: ABdhPJxB2P3j1owrvGBBA51LUg1ekoH9DvCk0WEK/LUtyibxQX3C/gmnE0vsgFTNXj3iG8L9lUyXww==
X-Received: by 2002:ac2:51a1:: with SMTP id f1mr1956784lfk.173.1592318898685;
        Tue, 16 Jun 2020 07:48:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:43bb:: with SMTP id t27ls1261728lfl.3.gmail; Tue, 16 Jun
 2020 07:48:18 -0700 (PDT)
X-Received: by 2002:ac2:5f07:: with SMTP id 7mr1977636lfq.132.1592318897993;
        Tue, 16 Jun 2020 07:48:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592318897; cv=none;
        d=google.com; s=arc-20160816;
        b=TItn9/wJ0qyp/CE8YUuFN0OA8NqMxa1UomFniATqeUx+75//BrG5Ch7NRr9D2wzSkT
         nDR+bODo63JNCNLP97VRjWsVFmwcnSviQo1W65H1g4Pi0fh0KmgiDEQ/2JGz2qwE5COu
         tAu/r4AYEnFRkVqL2Y9XloR/iQIXjS4b2iK62GVjApnEYHk+eaCna+MKeqcWUPZlNNYv
         EiEpAp92KYZAtxNjK+BNJYcEhxzl5nPaJGBGJU57N0CQrpbUV9QG8zj2cfTNfFtKKsz/
         TabR58GP60mzslS8wqxv407i/z6EtvyqCO2GHDxXscdvKeiQK5HgWkvZSgzQLHp77B3U
         VfSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :mail-followup-to:reply-to:message-id:subject:cc:to:from:date;
        bh=4K0eW0ggifXqVlYAC35Vz14GwOf9aNQMjH56rndewAg=;
        b=AJ/aTZn6qtDjNFU1Y5m330iyNSqbzRl/oBRsUlDmbBrgJWnCk7iv8B83B91KVvvQVt
         GQNXnMSkrInmg3/C6bCF2tiSd0gwn8miUtPfOb6YC8XjMlws9OxJ+lodf616doa4srKA
         kzKdxwKWgpP0Rq3QLWO+mVsmgVjd1Bdl4L35JSAuIMpxN44eYq52yfGR/Re9JIhxBLgw
         9y2bWClzjyooOx29NHUnJkTFGLvMNoZw9YCGR7dSKttc0wyn8pOz4uBfwQFZ183o1Q64
         TAMwlG3n8nNnCy4Qmz+QJdCutyTUbo9+2QwhfFo28i+mlCvIOAZrfleT5gR2jJEsT2cj
         THNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dsterba@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=dsterba@suse.cz
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id i17si1390204ljj.5.2020.06.16.07.48.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Jun 2020 07:48:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of dsterba@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx2.suse.de (Postfix) with ESMTP id 3F73AAAE8;
	Tue, 16 Jun 2020 14:48:18 +0000 (UTC)
Received: by ds.suse.cz (Postfix, from userid 10065)
	id 50CC9DA7C3; Tue, 16 Jun 2020 16:48:04 +0200 (CEST)
Date: Tue, 16 Jun 2020 16:48:04 +0200
From: David Sterba <dsterba@suse.cz>
To: Waiman Long <longman@redhat.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	David Howells <dhowells@redhat.com>,
	Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Joe Perches <joe@perches.com>, Matthew Wilcox <willy@infradead.org>,
	David Rientjes <rientjes@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	David Sterba <dsterba@suse.cz>,
	"Jason A . Donenfeld" <Jason@zx2c4.com>, linux-mm@kvack.org,
	keyrings@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-pm@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-amlogic@lists.infradead.org,
	linux-mediatek@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
	virtualization@lists.linux-foundation.org, netdev@vger.kernel.org,
	linux-ppp@vger.kernel.org, wireguard@lists.zx2c4.com,
	linux-wireless@vger.kernel.org, devel@driverdev.osuosl.org,
	linux-scsi@vger.kernel.org, target-devel@vger.kernel.org,
	linux-btrfs@vger.kernel.org, linux-cifs@vger.kernel.org,
	linux-fscrypt@vger.kernel.org, ecryptfs@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-bluetooth@vger.kernel.org,
	linux-wpan@vger.kernel.org, linux-sctp@vger.kernel.org,
	linux-nfs@vger.kernel.org, tipc-discussion@lists.sourceforge.net,
	linux-security-module@vger.kernel.org,
	linux-integrity@vger.kernel.org
Subject: Re: [PATCH v4 3/3] btrfs: Use kfree() in
 btrfs_ioctl_get_subvol_info()
Message-ID: <20200616144804.GD27795@twin.jikos.cz>
Reply-To: dsterba@suse.cz
Mail-Followup-To: dsterba@suse.cz, Waiman Long <longman@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Howells <dhowells@redhat.com>,
	Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Joe Perches <joe@perches.com>, Matthew Wilcox <willy@infradead.org>,
	David Rientjes <rientjes@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Jason A . Donenfeld" <Jason@zx2c4.com>, linux-mm@kvack.org,
	keyrings@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-pm@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-amlogic@lists.infradead.org,
	linux-mediatek@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
	virtualization@lists.linux-foundation.org, netdev@vger.kernel.org,
	linux-ppp@vger.kernel.org, wireguard@lists.zx2c4.com,
	linux-wireless@vger.kernel.org, devel@driverdev.osuosl.org,
	linux-scsi@vger.kernel.org, target-devel@vger.kernel.org,
	linux-btrfs@vger.kernel.org, linux-cifs@vger.kernel.org,
	linux-fscrypt@vger.kernel.org, ecryptfs@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-bluetooth@vger.kernel.org,
	linux-wpan@vger.kernel.org, linux-sctp@vger.kernel.org,
	linux-nfs@vger.kernel.org, tipc-discussion@lists.sourceforge.net,
	linux-security-module@vger.kernel.org,
	linux-integrity@vger.kernel.org
References: <20200616015718.7812-1-longman@redhat.com>
 <20200616015718.7812-4-longman@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200616015718.7812-4-longman@redhat.com>
User-Agent: Mutt/1.5.23.1-rc1 (2014-03-12)
X-Original-Sender: dsterba@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dsterba@suse.cz designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=dsterba@suse.cz
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

On Mon, Jun 15, 2020 at 09:57:18PM -0400, Waiman Long wrote:
> In btrfs_ioctl_get_subvol_info(), there is a classic case where kzalloc()
> was incorrectly paired with kzfree(). According to David Sterba, there
> isn't any sensitive information in the subvol_info that needs to be
> cleared before freeing. So kfree_sensitive() isn't really needed,
> use kfree() instead.
> 
> Reported-by: David Sterba <dsterba@suse.cz>
> Signed-off-by: Waiman Long <longman@redhat.com>
> ---
>  fs/btrfs/ioctl.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/fs/btrfs/ioctl.c b/fs/btrfs/ioctl.c
> index f1dd9e4271e9..e8f7c5f00894 100644
> --- a/fs/btrfs/ioctl.c
> +++ b/fs/btrfs/ioctl.c
> @@ -2692,7 +2692,7 @@ static int btrfs_ioctl_get_subvol_info(struct file *file, void __user *argp)
>  	btrfs_put_root(root);
>  out_free:
>  	btrfs_free_path(path);
> -	kfree_sensitive(subvol_info);
> +	kfree(subvol_info);

I would rather merge a patch doing to kzfree -> kfree instead of doing
the middle step to switch it to kfree_sensitive. If it would help
integration of your patchset I can push it to the next rc so there are
no kzfree left in the btrfs code. Treewide change like that can take
time so it would be one less problem to care about for you.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200616144804.GD27795%40twin.jikos.cz.
