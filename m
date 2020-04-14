Return-Path: <kasan-dev+bncBCIJL6NQQ4CRBY7C232AKGQEKMIQ7EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id D6A391A7B2A
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 14:49:39 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id y1sf4187075wmj.3
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 05:49:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586868579; cv=pass;
        d=google.com; s=arc-20160816;
        b=jFhZdE+yHAQEMRPlbZDf/8AcZ2GqosSpIszIrNAvP7C+2pYMyQyxQJOUgJK8k7Tm+A
         7eg+ksd7nF79zaJ8svWH1eoDO7m8iGoL4/oFoK8gV5bVBaakAdcjnWbYuqnqJTqw68dS
         j9QMU4Sur2MQcfM9jz0QLPPcpFtJ96wnJDfYMVjz//xY/qz0PO7ZK8heAIvQ8bqxkkcQ
         FgTyIwyyuQEqIB1bjnj8et9rLLVvnSQrLTvyxRzY1qL+LBBaoamXuvXMlWv9csMc7Q7Y
         dE2XOD7379SEyk6+UkNMw1eyzn2eqPVrheq3QhPUYrMLLZOnPHixB0ApHAv1xYa+7WPR
         3cCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:mail-followup-to
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=KNyPsRznKfpKeCATRI3PNzgIywhdqrKqHskEg8Eq+38=;
        b=UDOVANm9iH2aF4+T3gpyXurjrGPbPo6Zy4Sjb+Vmf8TcnsWuuClu2FQ+0SUoCGgEyt
         to+Z95DVRO5P3TlVoRl0L0TjykB0gTXt2y9JGCv2wiuLJGkaXvg88YcHZM6CPrcyioqi
         LcxjTXCcfUdWLstc57UbiRhdck2D5+FM3DE+nKHDkIblIm2/dicG5nEYeI61OZcIitOr
         AyO/qj309je5n4pKpoHPEw7VmJMHGbaeT721gT2TV8aKEAu18GrtTFMVWEUz6ET6/iMg
         N3ri3t8630ZZbzpxSUJ8D04uwfdWm6i+uWib0vb0RDyKq7SRIul0FHWfN1bVUes6NeOD
         YmDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dsterba@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=dsterba@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:mail-followup-to
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KNyPsRznKfpKeCATRI3PNzgIywhdqrKqHskEg8Eq+38=;
        b=QNifpuc/Drz4Jqny+9iNMvxfkPNMVCHImLskBC5KeZN6gAJz5oC2EPxjhL77Br8+gB
         JX5egSLtuO2lZf6gOVfU6Ek5LJ5EZSw0Rv6CSJMmPwWZOi39psqeEsBz63HCZJq4QgaL
         u/kQ2TubZTEZ/uemg2sq8MPG7d5yRag5gNJq+rmZ41ZVli0oLyK4+/d3fLyo/4JZC70j
         5eP9DslCBwrVCeEHf4ClgMF6labGQ/PDRPNjmzHFNwp+HPOG/e6IdqhsQ9JLO/KAFm/z
         L6tcz9zaOooVEEPfde4IpxByDhb6GQhR4cpmwpW7LjYdT2vcmdXDWDVJnv93VGOFztMb
         7mrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:mail-followup-to:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KNyPsRznKfpKeCATRI3PNzgIywhdqrKqHskEg8Eq+38=;
        b=Fyt0nR4KAjxu28k0QSMit82Hj34hE5phoWNmThIHHhNO9boO4l22rNh0Kz+Fp9K2Ti
         26IgV+3BMjQj8wjPVXQ8WxaF35ts9FjL8SdiDa0d0tZYdebxy4oxt/4BFLPRbn5dGHXG
         PUCUqBQobiMYg1vhkdfhbzLKkNlGiQUTptB/djelgveEgew3Q1GF8dmmAY0t7YkvlI0v
         AvKEd5iN6XMgICpuPe3SIVjUbOKBxC+5yklfnZndM/Y87y91WyER8MpU5I8BrEp5wf+A
         ISgEEF1FDTwpsylNhKq8GOM/NmC8rbndMXcqS44ER/tNk1BUKcXL/MibP2dsff1c6JmI
         YhZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYUvnMOGgWtfITO0dBje5bOZ6lhuRd5l1LWSe/cTr65DoKwh6cA
	yDvK37pK63du0knfw7+R1G4=
X-Google-Smtp-Source: APiQypLkPN6CWBAorW+vLoSUWAYMNaqhIuhY/k2eoLx3TprdvJqVy3g8uBaNnvssjDbNnpefNrRGWg==
X-Received: by 2002:a5d:44c6:: with SMTP id z6mr17308291wrr.192.1586868579616;
        Tue, 14 Apr 2020 05:49:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4a83:: with SMTP id o3ls2431415wrq.7.gmail; Tue, 14 Apr
 2020 05:49:39 -0700 (PDT)
X-Received: by 2002:a5d:6645:: with SMTP id f5mr24905128wrw.280.1586868579169;
        Tue, 14 Apr 2020 05:49:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586868579; cv=none;
        d=google.com; s=arc-20160816;
        b=hCZbcG7oO9daXyJEOk3svUZopn9OIEBBWMr1GgBMrERK+5Wc7VQB9x/TwJU9Z21DQx
         qDzkXv3XBum5NMOwUkfzwa6TLKymIN527qt3jdIq2+nYFgJWPf1mazjlNqyO6xilmvao
         Wl6cBLOpnm2bM/zoaZ3r3gEHMdimIYAgrhdig2fiSUtK3az03mwJ30v5bWvcaUnYkuew
         6YnVReCDjsBf8OKYTLxoJRyTnOBEbjv0wCUEwQMHO9UgO2LCckl6LSQIrHINpDOA16J2
         W7M5CT84/AYroENtKtziDfAI90uqhggwLUvESLti8vnxh/yr+s+u83L7WL2ErSubforC
         t93Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :mail-followup-to:reply-to:message-id:subject:cc:to:from:date;
        bh=Hz3svUSK0r182U35xJa9ZW4cSE7MP0oPmq3YFpfb5rw=;
        b=b5gr43Kud7B+6b0QE+rOtjQ+wbZTDTIqKNQ/vcYkdtZRz6dWaeVeSuFP6LS1MhDQW0
         EcA6b6VL6qK/EBP+drHlMgk3R16GdgWUMqqewCw5ku2qJqwudW9cDKlrJ4b7HRrd8TV+
         i48W92kw3dlYTcPWTqjzpzgifC9cOq0L8QP2oabO5T+Xla8dN6cbi0J9PZKfLmdz3Y1o
         YyY+n/tgOijH9DKQsaZ8mhohQaZjHHvF16Hsad5iseWOH6SRkvFIKwG4SzGfLC7jo3md
         r2+4fNqPmU1SGtDeb8lq6t8I+zG6Jx2dKoW8RkPQfjp4kczF1GBSLYmyaB92SVtKvX15
         z0TQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dsterba@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=dsterba@suse.cz
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id y1si506982wrh.1.2020.04.14.05.49.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Apr 2020 05:49:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of dsterba@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx2.suse.de (Postfix) with ESMTP id 6EF73AA7C;
	Tue, 14 Apr 2020 12:49:36 +0000 (UTC)
Received: by ds.suse.cz (Postfix, from userid 10065)
	id E5E76DA72D; Tue, 14 Apr 2020 14:48:54 +0200 (CEST)
Date: Tue, 14 Apr 2020 14:48:54 +0200
From: David Sterba <dsterba@suse.cz>
To: Waiman Long <longman@redhat.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	David Howells <dhowells@redhat.com>,
	Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Joe Perches <joe@perches.com>, Matthew Wilcox <willy@infradead.org>,
	David Rientjes <rientjes@google.com>, linux-mm@kvack.org,
	keyrings@vger.kernel.org, linux-kernel@vger.kernel.org,
	x86@kernel.org, linux-crypto@vger.kernel.org,
	linux-s390@vger.kernel.org, linux-pm@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-arm-kernel@lists.infradead.org,
	linux-amlogic@lists.infradead.org,
	linux-mediatek@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
	virtualization@lists.linux-foundation.org, netdev@vger.kernel.org,
	intel-wired-lan@lists.osuosl.org, linux-ppp@vger.kernel.org,
	wireguard@lists.zx2c4.com, linux-wireless@vger.kernel.org,
	devel@driverdev.osuosl.org, linux-scsi@vger.kernel.org,
	target-devel@vger.kernel.org, linux-btrfs@vger.kernel.org,
	linux-cifs@vger.kernel.org, samba-technical@lists.samba.org,
	linux-fscrypt@vger.kernel.org, ecryptfs@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-bluetooth@vger.kernel.org,
	linux-wpan@vger.kernel.org, linux-sctp@vger.kernel.org,
	linux-nfs@vger.kernel.org, tipc-discussion@lists.sourceforge.net,
	cocci@systeme.lip6.fr, linux-security-module@vger.kernel.org,
	linux-integrity@vger.kernel.org
Subject: Re: [PATCH 1/2] mm, treewide: Rename kzfree() to kfree_sensitive()
Message-ID: <20200414124854.GQ5920@twin.jikos.cz>
Reply-To: dsterba@suse.cz
Mail-Followup-To: dsterba@suse.cz, Waiman Long <longman@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Howells <dhowells@redhat.com>,
	Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Joe Perches <joe@perches.com>, Matthew Wilcox <willy@infradead.org>,
	David Rientjes <rientjes@google.com>, linux-mm@kvack.org,
	keyrings@vger.kernel.org, linux-kernel@vger.kernel.org,
	x86@kernel.org, linux-crypto@vger.kernel.org,
	linux-s390@vger.kernel.org, linux-pm@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-arm-kernel@lists.infradead.org,
	linux-amlogic@lists.infradead.org,
	linux-mediatek@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
	virtualization@lists.linux-foundation.org, netdev@vger.kernel.org,
	intel-wired-lan@lists.osuosl.org, linux-ppp@vger.kernel.org,
	wireguard@lists.zx2c4.com, linux-wireless@vger.kernel.org,
	devel@driverdev.osuosl.org, linux-scsi@vger.kernel.org,
	target-devel@vger.kernel.org, linux-btrfs@vger.kernel.org,
	linux-cifs@vger.kernel.org, samba-technical@lists.samba.org,
	linux-fscrypt@vger.kernel.org, ecryptfs@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-bluetooth@vger.kernel.org,
	linux-wpan@vger.kernel.org, linux-sctp@vger.kernel.org,
	linux-nfs@vger.kernel.org, tipc-discussion@lists.sourceforge.net,
	cocci@systeme.lip6.fr, linux-security-module@vger.kernel.org,
	linux-integrity@vger.kernel.org
References: <20200413211550.8307-1-longman@redhat.com>
 <20200413211550.8307-2-longman@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200413211550.8307-2-longman@redhat.com>
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

On Mon, Apr 13, 2020 at 05:15:49PM -0400, Waiman Long wrote:
>  fs/btrfs/ioctl.c                              |  2 +-


> diff --git a/fs/btrfs/ioctl.c b/fs/btrfs/ioctl.c
> index 40b729dce91c..eab3f8510426 100644
> --- a/fs/btrfs/ioctl.c
> +++ b/fs/btrfs/ioctl.c
> @@ -2691,7 +2691,7 @@ static int btrfs_ioctl_get_subvol_info(struct file *file, void __user *argp)
>  	btrfs_put_root(root);
>  out_free:
>  	btrfs_free_path(path);
> -	kzfree(subvol_info);
> +	kfree_sensitive(subvol_info);

This is not in a sensitive context so please switch it to plain kfree.
With that you have my acked-by. Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200414124854.GQ5920%40twin.jikos.cz.
