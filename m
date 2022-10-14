Return-Path: <kasan-dev+bncBCIJL6NQQ4CRBIGRUSNAMGQESZ363WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id AAEEA5FEB61
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Oct 2022 11:15:12 +0200 (CEST)
Received: by mail-ej1-x63b.google.com with SMTP id hd11-20020a170907968b00b0078df60485fdsf1969244ejc.17
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Oct 2022 02:15:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665738912; cv=pass;
        d=google.com; s=arc-20160816;
        b=QKrsEzFW1VsCt/gfzyHcfVaqnVLjnjijfHB8TfjAadLOod1y+z5ZmGp2TkyF2rlRrW
         WvS7GMxk0SwBXAQhSFMaVER/PPjJusjEDQxKVRVlIQu/sxzDgjSPUjTSlHAn8kG5lfAH
         YYsCWy8ucIVD93vWuOSCgK7QXFnO6Tb2XUpXgBA7Po20lumQ7xgQat1xaCbrQfKR59to
         IUB/LR3N02uPkyDPg0bqE/AjAFrtK6uxehOQIWTE+asrT5tuXuo4Ybr3e81yJUshOFkb
         RgwdeAtbueRXgpmlbfcsLlLLejURdYXr54VCq1LV9BKlyATLj0WXkri6OWG8GGHv1nVL
         rVZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=+4qkZ1nuAtp6gptiRnPdeZk9Yz9wfeanuhsXufqAB94=;
        b=chjavXK4odEx6nw72CvKyqdSFfPcC8YWw2Qiz+klZhmbmmAxPQwK0EqQM24QCOBivE
         kmUkDCWdqQ7JWesmVLGYP2ULCiKrdAifjM+FO1GqvxY1bnS4W50YFHmtMule/VqnB14c
         yd7F6ky3ehxTrui3vQmC121xsnyxQY/0xldKGSlWkSjHTz+gL07pwfYG1KEzmp002Fya
         n0z2zZz5Gnn68RhZ6YhOUciFiv9diRbcmgT7u0hTNUgpfW8eDcQ8qMuMcagl89uQgAyv
         WENAo7UqeakkRfy77kCjGItossBrFO1v61gGIiQl+xuc+hFB254JdF5hns4R8LPvP0/Z
         f/pQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=tbFHpqFR;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=STUhXyiy;
       spf=softfail (google.com: domain of transitioning dsterba@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=dsterba@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+4qkZ1nuAtp6gptiRnPdeZk9Yz9wfeanuhsXufqAB94=;
        b=M1xN8a9TANPghfnmAuzPii6qgiDLnr2duIuFmOFFwh6lxWwavRD3Znc4yzwTLbCmKb
         Of1eL0P8a5UeNmEykeSU8D85IuYJkjXd4nNGcPttrXT/tO4uYrntZ8/AmNaZ9XmfOd0O
         69+2dVWiwaN8sZkG+a/5ZU+8O80DZF3kO9DFR6sln/WqgFVjP54axpLVErdvRl8GIguE
         MaUWAYiYQhwtFY7+CfU1chKE2k9x1TkxCnxr5wLogkqkcPneEFUkvStkFRVQYpQEDn0S
         9inAp+0aZtvXDmOfM6yuu+5Epnb3D6g/aSHBBKSd6Q52fg5v6Ok7l5W5ewwivQMQN84E
         InHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=+4qkZ1nuAtp6gptiRnPdeZk9Yz9wfeanuhsXufqAB94=;
        b=yxgCFOHDpzGwc351QOsMjpq+SR1m7ToIONZoOtpaq1txB7121aVrU3Cx+/5iONwGAq
         tfROmz1FN5oFGX24ig3QwzmCRKWGrXn3yqfISfmQXqk81mlQ9AiEdRHaFAXjJKXP2Xj6
         25uQiAOgzD2FnbkOLnX46R0gLHXQsMGi658TBW7ZG/O/HKpUP4YLrfofhtTCZO3g10XT
         UKK0E0HAyhpvRUFyVINLTa4/0fSAYDkJ/sZF6TVBxkB5czCnli1PwnUK3XCIhskPoBxq
         cx6MHlalNkb6OdKWTvFq4GItvCK5sS5bN5+mEd90kqaZ3uKUb4WjQ1P9YFywqlB5XT9Y
         +L8Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0nFjGd8xA9RCO86T+oPJCH4bW/qNF2nwuEkHR/HF3R9nZkJR+/
	8o6BMLQKKMkd8jqlgm4ymy8=
X-Google-Smtp-Source: AMsMyM5hQr3/WqeTrBiPzfc3rc05Ye0tZ/i3H9T82sLy6BlBGta6eMDLffkw0LUbIzzHRdD3stWyYg==
X-Received: by 2002:a05:6402:26c2:b0:45c:1fef:ee1d with SMTP id x2-20020a05640226c200b0045c1fefee1dmr3397689edd.13.1665738912202;
        Fri, 14 Oct 2022 02:15:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:10cc:b0:78d:14b3:67b2 with SMTP id
 rv12-20020a17090710cc00b0078d14b367b2ls2223899ejb.7.-pod-prod-gmail; Fri, 14
 Oct 2022 02:15:11 -0700 (PDT)
X-Received: by 2002:a17:906:ee86:b0:741:89bc:27a1 with SMTP id wt6-20020a170906ee8600b0074189bc27a1mr2860400ejb.725.1665738911057;
        Fri, 14 Oct 2022 02:15:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665738911; cv=none;
        d=google.com; s=arc-20160816;
        b=ZJld6nM/Gjy4CYuQPjJfqlhXT8wBxUfXHovk+81jVWI3Iq9yMNz20Pg9w6ECnQR7Rf
         sgSkl0sQM6k+5M7BNZSKX44laoJSpjd+iNY1IERzugyQwAhY30YxOK9kdXUyyFIcTIwp
         0VjV29bATLAOJ+9qO+dJeIRBAVDolMO/v+Vvx591YAeU+KxuzSlJCI8cmLJ3z3g3VZQl
         h80/0wDV4echidu1NisZPPvlZ5QN4y0wFPxwPlXY11aK18yzqltWJ9aef31fU/m8BJeh
         k6ksxLP3qfoZiBAFlyLciC/K820xrEMZt1yKP5Gyx0y7sEEV1CEZzU4g1FN68nRXU8Jj
         VVMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature
         :dkim-signature;
        bh=Lop39TQqCOXXxSbDsyQkXoUBrxToIIED3a6P4bzyLLs=;
        b=Q5P57e831J1qaTCB9ET3NP/Gr5f9bYqoHCuWLCDgA+fv8qm2CzJmJf/UKw0ekM0+T9
         Z8EbCQGfZYDL5zxD352SkS5sNS0rqODIy57Fe1imLRJ6tnMuA4kqotPHzJWfgM/Qkaiv
         uQ0MAy83Gvdv3jbUwhG4fMbgDYm9JlI4ZXaXWKveNs2WoPGUDM3nF62gBBkM15XLQ39U
         VmndUFCU7L4QSxBYyCedW8jwMcQGjKIHceb3J1zuPqxndtU2gvT3+o71hfXDTfit0qDM
         sYNcAbakCDOq3KVaW/DSIQb2HxZiTi1QDA4AteBvNldUjriIKwIOaRm8uLwJ66CuiWq4
         pP7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=tbFHpqFR;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=STUhXyiy;
       spf=softfail (google.com: domain of transitioning dsterba@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=dsterba@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id a16-20020aa7cf10000000b004595ce68e4asi72030edy.5.2022.10.14.02.15.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 Oct 2022 02:15:11 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning dsterba@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id A54BF1F383;
	Fri, 14 Oct 2022 09:15:10 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 2F10613451;
	Fri, 14 Oct 2022 09:15:10 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id EbSrCp4oSWM1GQAAMHmgww
	(envelope-from <dsterba@suse.cz>); Fri, 14 Oct 2022 09:15:10 +0000
Date: Fri, 14 Oct 2022 11:15:03 +0200
From: David Sterba <dsterba@suse.cz>
To: Hrutvik Kanabar <hrkanabar@gmail.com>
Cc: Hrutvik Kanabar <hrutvik@google.com>, Marco Elver <elver@google.com>,
	Aleksandr Nogikh <nogikh@google.com>, kasan-dev@googlegroups.com,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org,
	Theodore Ts'o <tytso@mit.edu>,
	Andreas Dilger <adilger.kernel@dilger.ca>,
	linux-ext4@vger.kernel.org, Chris Mason <clm@fb.com>,
	Josef Bacik <josef@toxicpanda.com>, David Sterba <dsterba@suse.com>,
	linux-btrfs@vger.kernel.org, Jaegeuk Kim <jaegeuk@kernel.org>,
	Chao Yu <chao@kernel.org>, linux-f2fs-devel@lists.sourceforge.net,
	"Darrick J . Wong" <djwong@kernel.org>, linux-xfs@vger.kernel.org,
	Namjae Jeon <linkinjeon@kernel.org>,
	Sungjong Seo <sj1557.seo@samsung.com>,
	Anton Altaparmakov <anton@tuxera.com>,
	linux-ntfs-dev@lists.sourceforge.net
Subject: Re: [PATCH RFC 0/7] fs: Debug config option to disable filesystem
 checksum verification for fuzzing
Message-ID: <20221014091503.GA13389@twin.jikos.cz>
Reply-To: dsterba@suse.cz
References: <20221014084837.1787196-1-hrkanabar@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20221014084837.1787196-1-hrkanabar@gmail.com>
User-Agent: Mutt/1.5.23.1-rc1 (2014-03-12)
X-Original-Sender: dsterba@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=tbFHpqFR;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=STUhXyiy;
       spf=softfail (google.com: domain of transitioning dsterba@suse.cz does
 not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=dsterba@suse.cz
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

On Fri, Oct 14, 2022 at 08:48:30AM +0000, Hrutvik Kanabar wrote:
> From: Hrutvik Kanabar <hrutvik@google.com>
> 
> Fuzzing is a proven technique to discover exploitable bugs in the Linux
> kernel. But fuzzing filesystems is tricky: highly structured disk images
> use redundant checksums to verify data integrity. Therefore,
> randomly-mutated images are quickly rejected as corrupt, testing only
> error-handling code effectively.
> 
> The Janus [1] and Hydra [2] projects probe filesystem code deeply by
> correcting checksums after mutation. But their ad-hoc
> checksum-correcting code supports only a few filesystems, and it is
> difficult to support new ones - requiring significant duplication of
> filesystem logic which must also be kept in sync with upstream changes.
> Corrected checksums cannot be guaranteed to be valid, and reusing this
> code across different fuzzing frameworks is non-trivial.
> 
> Instead, this RFC suggests a config option:
> `DISABLE_FS_CSUM_VERIFICATION`. When it is enabled, all filesystems
> should bypass redundant checksum verification, proceeding as if
> checksums are valid. Setting of checksums should be unaffected. Mutated
> images will no longer be rejected due to invalid checksums, allowing
> testing of deeper code paths. Though some filesystems implement their
> own flags to disable some checksums, this option should instead disable
> all checksums for all filesystems uniformly. Critically, any bugs found
> remain reproducible on production systems: redundant checksums in
> mutated images can be fixed up to satisfy verification.
> 
> The patches below suggest a potential implementation for a few
> filesystems, though we may have missed some checksums. The option
> requires `DEBUG_KERNEL` and is not intended for production systems.
> 
> The first user of the option would be syzbot. We ran preliminary local
> syzkaller tests to compare behaviour with and without these patches.
> With the patches, we found a 19% increase in coverage, as well as many
> new crash types and increases in the total number of crashes:

I think the build-time option inflexible, but I see the point when
you're testing several filesystems that it's one place to set up the
environment. Alternatively I suggest to add sysfs knob available in
debuging builds to enable/disable checksum verification per filesystem.

As this may not fit to other filesystems I don't suggest to do that for
all but I am willing to do that for btrfs, with eventual extension to
the config option you propose. The increased fuzzing coverage would be
good to have.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221014091503.GA13389%40twin.jikos.cz.
