Return-Path: <kasan-dev+bncBCIJL6NQQ4CRBWM6UX3QKGQE2VZENZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F6F11FC1FC
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 01:01:46 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id e15sf35771lfq.5
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 16:01:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592348506; cv=pass;
        d=google.com; s=arc-20160816;
        b=w+zby+3Ge5ZZOzYhu8GbS+A2sMDhYBmIRbByJfCSLFrvqy16/BucP4JQZudcan91Fp
         9C3upHbXPgP5GmaLAOEJShjPJy+JaP1Kz6g84k8uYqczEjTha6HH/5l4v9439XJZsJed
         19w126trJYAnlqq8QfE2dsH1az1lcJyGxHm5usojS7xFiHVN0YnpcaNZc/LtFZ19lzQO
         Imy9Dpu2/gzRHT1VOeY5txNYX+K2LmnMUYgMVg1qzNiqaxQW8gQtZgUnBnB0j+c72JFC
         Szm0FxSY/qYZWQ0vlOhnjB6SlylFfVggeNNq2NCQc+SxC+zKtGQfOcutL0HAV4wtyqME
         pk3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:mail-followup-to
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=ZJ+LJewGR98JKxfu+3PvqlBCZPtnBO2i7ZiqoP0K1ko=;
        b=a8hvoQkkQPmJVUXBg2HGu89PsS7wSCwhmGk9yVY5nmed+BIE6tSwL3kdZyWqs45a7h
         hwNdHclKS6RrqmoeKcgtZgKEQhuDlbLXvvW+e+49jTEj3CTDokj+sL81wp8dcHS1Cww2
         RNBBlNCFglrRr5B+D+6629HHFXY5Wl0LKbtBxO7Gk11FA1TsA7dhR+43bSj1BdMWYJ+0
         sovjiiQQss1g8bYjiwj8FPRHWiDiI3HtucLDhhyz5vrJA0UaIybnZHuFVikTXJIj3b73
         613nrQ4TQHmcI0Gfhg+i8oNI+I8uCbZSiVvySSdiQup8hl8xfPvSUMlueh+KAgBi1Jyo
         EMQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dsterba@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=dsterba@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:mail-followup-to
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZJ+LJewGR98JKxfu+3PvqlBCZPtnBO2i7ZiqoP0K1ko=;
        b=XQOBB5HD3FABHbK5MswOj3JEF3d0noqkKDcnLfFx2h544f0swYk+3bJpWBPH6LAja1
         GBAKKPAqEiGw1EVSzrX2MID5ZASMpJ1Z3+/ColmC4MaEdt/9y7t2F32uIyhfTe55OmdL
         Wxq3B/kBtCW/nYtcpiA9L6Nnbbpkh9H6WjPbz7TLGAVqmSpQJ4LRz4FxDWPTjTFX/fD7
         dn7AT7cE5DWbmJ6UEDUeG4WIP5+QmMFVlG71Mck5bvStENA6B6Yb0ARoWXhpo1n2sccG
         8Q2PVKUcQI56BspD4sy171vzYrUR1Y0s/hmPbZQVN+Ua1hqI50hXcc7v58TN8Fbu663F
         rEFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:mail-followup-to:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZJ+LJewGR98JKxfu+3PvqlBCZPtnBO2i7ZiqoP0K1ko=;
        b=aASInCY0jXt6WuRHD0O4QmBMfPBMK1iyx/VS9AJf6Ab6tTJNaCfb71eLdX3vnsi4C8
         xes1YjzZWlU1UpOzq9IGuIsLW1wcs8PW5TgYU89MrdBleWHJJVd3fVs2FQvy4WIKqRsL
         9kQ/Zlzh8H5gHDYA/A8BdA+XY6Nh2G0E6wgaxFEUHQwYEW1OFcmd0MG2pZVxrMJrZOFH
         Q+WVDmFgDRmUwFlQmG7/vs7kFwg5FiUw7xzoSoSt49T9RdqqKRLuYpY5uCp6Zyurrkkv
         ymXMrNZcFvQHb0X2gDgCzH0wgoBx4awGvchQsVxmPCrrjCcPg9VPXD3aZRx5o6oRDTQM
         /h/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530N/OLYj7cHDyQZjEyvsodKHjlpPb3fjtmKdAOAJpwOn88AAilw
	1RCopXUrNI1wdmt4B5yeEF8=
X-Google-Smtp-Source: ABdhPJxNmMrxmZpYA21bCybJQzVknvcj0Mrd/LyVbeZ+eP9NiV5jPwU3UPUNAX8/0X9Khz8hiM5shQ==
X-Received: by 2002:a05:651c:383:: with SMTP id e3mr2633733ljp.386.1592348505839;
        Tue, 16 Jun 2020 16:01:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:be95:: with SMTP id o143ls63278lff.0.gmail; Tue, 16 Jun
 2020 16:01:45 -0700 (PDT)
X-Received: by 2002:a19:691c:: with SMTP id e28mr2909674lfc.131.1592348505241;
        Tue, 16 Jun 2020 16:01:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592348505; cv=none;
        d=google.com; s=arc-20160816;
        b=oKe8V233kWbF+D+jNuLFe6m2yxUJFTrwTeKW0Vec8/1NLKahFxM40XQFYYPRJQ6ohh
         vg2WGYzbzWQL6nf91MfOFvQRc7DLeRTLF13pnSW2MwfQMkaFPHpDFj+MmDEk1mFLCl7K
         8Bx+C5Wy5r7OQPOBVV/1/OcHHfcfjENMUGDjNyAB1GUPgr77mGR/QW45jbcfXgKEpfS9
         0u6Tk+Z41uQ8AHbtaadyZhxESNy74QV0f+dCFYPmbIyYOctxLYV57BnmqZZHvKzBJjCF
         QqHw+KptdivMH61rtJddnxDo8N9BC83d6NIbwU3gz4YemYP+l45H6+g/CySYccTQVQdd
         Z9nQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :mail-followup-to:reply-to:message-id:subject:cc:to:from:date;
        bh=/G0ZZo+hfIsLY4Hx8Xvj+acWQVOIsMnCIbV4R2nkWQE=;
        b=QrSfmU3bgC0t3HVc9wff97KTlPfRtmQh3/WCkXsn3tOnrXf28afOKLf7525+fL/yAo
         vl6lVmjFHcRategvw5GjgXhtVaR/O378vRZA9FFujry5KmYeUSvRNNLNbn3yJjXkOzsI
         5nE/g/cggI40gWNj5dB/A+W7ZteBMI70AV775gOb3Ula1llx9pzJff9jFwjWTzd/HTyG
         fHDWPXM9ou+xRANc0dNv213oPfmK+DWJ3mbVAQ3jVRbUcpX51zNbLQYMvEZ3NepYQi98
         7KlDXt/kYnGhY+1h08s4JJQ5gGOGqEXdHw6HrPs049ZsmpIYiNix2ashsBCpSxHtVGdY
         HiHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dsterba@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=dsterba@suse.cz
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id z3si428758lfe.5.2020.06.16.16.01.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Jun 2020 16:01:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of dsterba@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx2.suse.de (Postfix) with ESMTP id 6CB7AADA8;
	Tue, 16 Jun 2020 23:01:45 +0000 (UTC)
Received: by ds.suse.cz (Postfix, from userid 10065)
	id 1AC8EDA7C3; Wed, 17 Jun 2020 01:01:30 +0200 (CEST)
Date: Wed, 17 Jun 2020 01:01:30 +0200
From: David Sterba <dsterba@suse.cz>
To: Joe Perches <joe@perches.com>
Cc: Waiman Long <longman@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Howells <dhowells@redhat.com>,
	Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Matthew Wilcox <willy@infradead.org>,
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
Subject: Re: [PATCH v4 0/3] mm, treewide: Rename kzfree() to kfree_sensitive()
Message-ID: <20200616230130.GJ27795@twin.jikos.cz>
Reply-To: dsterba@suse.cz
Mail-Followup-To: dsterba@suse.cz, Joe Perches <joe@perches.com>,
	Waiman Long <longman@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Howells <dhowells@redhat.com>,
	Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Matthew Wilcox <willy@infradead.org>,
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
 <fe3b9a437be4aeab3bac68f04193cb6daaa5bee4.camel@perches.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <fe3b9a437be4aeab3bac68f04193cb6daaa5bee4.camel@perches.com>
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

On Tue, Jun 16, 2020 at 11:53:50AM -0700, Joe Perches wrote:
> On Mon, 2020-06-15 at 21:57 -0400, Waiman Long wrote:
> >  v4:
> >   - Break out the memzero_explicit() change as suggested by Dan Carpenter
> >     so that it can be backported to stable.
> >   - Drop the "crypto: Remove unnecessary memzero_explicit()" patch for
> >     now as there can be a bit more discussion on what is best. It will be
> >     introduced as a separate patch later on after this one is merged.
> 
> To this larger audience and last week without reply:
> https://lore.kernel.org/lkml/573b3fbd5927c643920e1364230c296b23e7584d.camel@perches.com/
> 
> Are there _any_ fastpath uses of kfree or vfree?

I'd consider kfree performance critical for cases where it is called
under locks. If possible the kfree is moved outside of the critical
section, but we have rbtrees or lists that get deleted under locks and
restructuring the code to do eg. splice and free it outside of the lock
is not always possible.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200616230130.GJ27795%40twin.jikos.cz.
