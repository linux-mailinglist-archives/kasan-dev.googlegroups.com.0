Return-Path: <kasan-dev+bncBCKMR55PYIGBB6ODYWPAMGQEWOHHJGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id CB50867B7E3
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 18:08:10 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id c66-20020a1c3545000000b003d355c13229sf1409456wma.0
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 09:08:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674666490; cv=pass;
        d=google.com; s=arc-20160816;
        b=EgkggI09pd/UDZYSL+khBdhFczcShZwrnqWKgXJfPp/SljnSC0x049CLxr/ao07MzI
         bX6AH+9vCcXMRmJvtOW+N4aKXrZR875cO3Byg4XdYLAH4thQy7DV1wU2x6ehm4/MNNt+
         QYuJNFHOlh5mcR2HybGXSasMmqAy/rvezLAu/WsswoL1Dm12d4XhjlJ99dVoIHSg08xs
         sdq9JJ9CskijXaz08bXoKL4036pRlKH8l2zHOsDqlVUspAK6MCHBJQMeiOcEBvp3eqir
         f22DtYEqRMjNPP207LnKtfOeHNrKQ0wEqn6tNqPao3MrYgf3Pn1UjPiYPSL8Mbb2pzYk
         7WIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=YV57VgY6Xm2QpbSmk+QC6lA0Qmcd+tJAomtCSJbzXFY=;
        b=iDQxTqUUTWQTVKVpYLJtRxZDcAlysOmM/dLUwgGSMukdp0B3idO7HIGX3VBw9cgRWf
         Bk14IhvdxTfl/bNyU8rRcyJ7LtOk3wr/jbn9plRLvGcFusKadLmh/vK736ADYtlczNzr
         vASBeraS9JENr5jIzhxmM1+aJ6cfcBhsj9uABkGs3FmnSBDBaVn7a+LqqXYHGmK7BW4O
         Yb6fRFDDFLeDrj0pZV9Ubn1/eAbqvsD1rT0ONlYUQywRUUbTgUe+R8VP8nzhLGG/QeSJ
         Gwm6IjrxCS/wkvwvyxu1Veh++u1myHSWcr2mzOn4SY1NAeC4tcw7Vg0gMS11V0ToPxAS
         Wd7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b="D/br1xSs";
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=YV57VgY6Xm2QpbSmk+QC6lA0Qmcd+tJAomtCSJbzXFY=;
        b=dIay4H3vPGbzikS48HdReyfivkGzk+XLFUPdVPcf8xZMwvjtHojLLqr2TyVYX+9rnw
         fP2rTQ7ZhOmQTm+76mgC0aSFKtBfy1R1SvSsnQdUu0mK74gBkODTUI7EbGdsC6RZ1Ib3
         KyxyJbS5cWfIJVFxUHsnRT0iWN917u5oraj3CH/XlslU5tzF5j1Jlla9nhbqYF/92Stn
         RwiUDaFI/7gSEmgRehoDKoEkv5VhXebT4lHCaPUenZPDtUGyDCj3bq/ODt9AN1yBEoVM
         s3fPuV9k8mWxfHsNLud8r9Puc1Qm3juWRpLkF9g2IHBpD8uLLs3gXchheWCAeYWufHgp
         ON8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YV57VgY6Xm2QpbSmk+QC6lA0Qmcd+tJAomtCSJbzXFY=;
        b=Q6LtgpFwK1+Ptj/N7+JyCvEwd7O2KYmTbboxlFSCcGKgiFmZAmM6dpc2OC475Bo1/2
         nK/4YYfQRq5QQGYzcSjI5QsVcHdV4RKzP1EsuagXq6k0XKI6UcQyj10pqXL74VfarHBG
         QzR+WcY2Weoq2li6X9AUNo5RgFLf7YWga0PtVtsXNq5i2qeObYfwPexbe2bQ6hzXRwH3
         RLtzPvWK7posHLiZJOP1eez9xMpRH4D0PgAdYQ7lTXDAFIuXyNuP9SwcvOWRgCOxJwhb
         vBtZY3AT8scPNe3pHhqWdlBBJwJsATbDiZ9y/eSx7dyZGIPowLcZTzvjhpk9hKXhEHJS
         GpLQ==
X-Gm-Message-State: AFqh2konapqAj3FwT/3tuP1BNRiThnZ3UOyOtpcY8f7NHq7URgYlpFrx
	9JijVyI7RIoUbqFZZgeZs5Y=
X-Google-Smtp-Source: AMrXdXttQc6lu5MGkGoXMDQY7R/5ajKgzmtrJI2G8fvDMHBFX5KcFqQ4yXCX8VEACzn7jWkFReAB5g==
X-Received: by 2002:adf:eb0b:0:b0:2be:5132:b7ed with SMTP id s11-20020adfeb0b000000b002be5132b7edmr1109866wrn.174.1674666489970;
        Wed, 25 Jan 2023 09:08:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d15:b0:3cd:d7d0:14b6 with SMTP id
 l21-20020a05600c1d1500b003cdd7d014b6ls1511239wms.1.-pod-control-gmail; Wed,
 25 Jan 2023 09:08:08 -0800 (PST)
X-Received: by 2002:a05:600c:4b16:b0:3d2:2830:b8bb with SMTP id i22-20020a05600c4b1600b003d22830b8bbmr40037069wmp.34.1674666488776;
        Wed, 25 Jan 2023 09:08:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674666488; cv=none;
        d=google.com; s=arc-20160816;
        b=qDxhabnpC54OnbOYpJG5gCTiuE/99xJfji4yJR3tKkzasj8qKaafoxhpnhxjp2qVlP
         hwbf9qxnbIVdBtNaEQJ3t3NdzDI5MJmY53qc/h+BhlV1TkZNCUmY79k6uGW9HGftARSG
         SMJ8ZuF6xEubbDdrkytcFP2h6Qw4M0mgsDFsCfP8AGADLrzc9SM5hqaqN8YWL/fn3YZS
         8y6qGIiYa9/PLra9icMOYjctJdSkXEx3iQ45Dc6Cm3+XYxbUjMDRk634dz9OM5Lvu8i1
         Qz4vi6AysxkG7XewmDEQfsPiZLygNaE9gRhj3KTVpB8w6KSgALX+0pMUSrL7dwMwMduS
         4Wow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=FNzsO8QkHd4bwcFXjgFFOOBC/xElVC4T91KIaFtN0Io=;
        b=txmdZMgm8xS56gvbdU1c4oN5YT7hc6LTp0x9iXinssx7+4gdRmKxsD5N0lybojykyJ
         E9OuMcS/PBosFT6EskWRySj4HSi/iJ4YBA6toJmFqG0QjQpte/y7VLocluXZpn93h0ai
         S6LHOnTT6y063gKugkDeVu9x2Nl7ek6MQMPqHbEYBCvVJuJIcp1h5E4RKj3RUGVRuTPQ
         HbdchHio1D/yrPwKMPLnNnUJCRzxg3FejjD6gtnMYM9n/hzVlJRvfv1jk29/AJjWUDrC
         zQUt2EhpbEwTARtJAwhb12RRoJ/aK4nvwHE4rSI9had83plFCO9FRgIr8LCwwQlJMykC
         lQBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b="D/br1xSs";
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id p33-20020a05600c1da100b003d9ae6cfd2esi165424wms.2.2023.01.25.09.08.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jan 2023 09:08:08 -0800 (PST)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id CD5621FD8D;
	Wed, 25 Jan 2023 17:08:07 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 7757F1358F;
	Wed, 25 Jan 2023 17:08:07 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id T+qcHPdh0WP1JAAAMHmgww
	(envelope-from <mhocko@suse.com>); Wed, 25 Jan 2023 17:08:07 +0000
Date: Wed, 25 Jan 2023 18:08:06 +0100
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, michel@lespinasse.org, jglisse@google.com,
	vbabka@suse.cz, hannes@cmpxchg.org, mgorman@techsingularity.net,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	peterz@infradead.org, ldufour@linux.ibm.com, paulmck@kernel.org,
	luto@kernel.org, songliubraving@fb.com, peterx@redhat.com,
	david@redhat.com, dhowells@redhat.com, hughd@google.com,
	bigeasy@linutronix.de, kent.overstreet@linux.dev,
	punit.agrawal@bytedance.com, lstoakes@gmail.com,
	peterjung1337@gmail.com, rientjes@google.com,
	axelrasmussen@google.com, joelaf@google.com, minchan@google.com,
	jannh@google.com, shakeelb@google.com, tatashin@google.com,
	edumazet@google.com, gthelen@google.com, gurua@google.com,
	arjunroy@google.com, soheil@google.com, hughlynch@google.com,
	leewalsh@google.com, posk@google.com, will@kernel.org,
	aneesh.kumar@linux.ibm.com, npiggin@gmail.com,
	chenhuacai@kernel.org, tglx@linutronix.de, mingo@redhat.com,
	bp@alien8.de, dave.hansen@linux.intel.com, richard@nod.at,
	anton.ivanov@cambridgegreys.com, johannes@sipsolutions.net,
	qianweili@huawei.com, wangzhou1@hisilicon.com,
	herbert@gondor.apana.org.au, davem@davemloft.net, vkoul@kernel.org,
	airlied@gmail.com, daniel@ffwll.ch,
	maarten.lankhorst@linux.intel.com, mripard@kernel.org,
	tzimmermann@suse.de, l.stach@pengutronix.de,
	krzysztof.kozlowski@linaro.org, patrik.r.jakobsson@gmail.com,
	matthias.bgg@gmail.com, robdclark@gmail.com,
	quic_abhinavk@quicinc.com, dmitry.baryshkov@linaro.org,
	tomba@kernel.org, hjc@rock-chips.com, heiko@sntech.de,
	ray.huang@amd.com, kraxel@redhat.com, sre@kernel.org,
	mcoquelin.stm32@gmail.com, alexandre.torgue@foss.st.com,
	tfiga@chromium.org, m.szyprowski@samsung.com, mchehab@kernel.org,
	dimitri.sivanich@hpe.com, zhangfei.gao@linaro.org,
	jejb@linux.ibm.com, martin.petersen@oracle.com,
	dgilbert@interlog.com, hdegoede@redhat.com, mst@redhat.com,
	jasowang@redhat.com, alex.williamson@redhat.com, deller@gmx.de,
	jayalk@intworks.biz, viro@zeniv.linux.org.uk, nico@fluxnic.net,
	xiang@kernel.org, chao@kernel.org, tytso@mit.edu,
	adilger.kernel@dilger.ca, miklos@szeredi.hu,
	mike.kravetz@oracle.com, muchun.song@linux.dev, bhe@redhat.com,
	andrii@kernel.org, yoshfuji@linux-ipv6.org, dsahern@kernel.org,
	kuba@kernel.org, pabeni@redhat.com, perex@perex.cz, tiwai@suse.com,
	haojian.zhuang@gmail.com, robert.jarzmik@free.fr,
	linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org,
	linuxppc-dev@lists.ozlabs.org, x86@kernel.org,
	linux-kernel@vger.kernel.org, linux-graphics-maintainer@vmware.com,
	linux-ia64@vger.kernel.org, linux-arch@vger.kernel.org,
	loongarch@lists.linux.dev, kvm@vger.kernel.org,
	linux-s390@vger.kernel.org, linux-sgx@vger.kernel.org,
	linux-um@lists.infradead.org, linux-acpi@vger.kernel.org,
	linux-crypto@vger.kernel.org, nvdimm@lists.linux.dev,
	dmaengine@vger.kernel.org, amd-gfx@lists.freedesktop.org,
	dri-devel@lists.freedesktop.org, etnaviv@lists.freedesktop.org,
	linux-samsung-soc@vger.kernel.org, intel-gfx@lists.freedesktop.org,
	linux-mediatek@lists.infradead.org, linux-arm-msm@vger.kernel.org,
	freedreno@lists.freedesktop.org, linux-rockchip@lists.infradead.org,
	linux-tegra@vger.kernel.org,
	virtualization@lists.linux-foundation.org,
	xen-devel@lists.xenproject.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-rdma@vger.kernel.org, linux-media@vger.kernel.org,
	linux-accelerators@lists.ozlabs.org, sparclinux@vger.kernel.org,
	linux-scsi@vger.kernel.org, linux-staging@lists.linux.dev,
	target-devel@vger.kernel.org, linux-usb@vger.kernel.org,
	netdev@vger.kernel.org, linux-fbdev@vger.kernel.org,
	linux-aio@kvack.org, linux-fsdevel@vger.kernel.org,
	linux-erofs@lists.ozlabs.org, linux-ext4@vger.kernel.org,
	devel@lists.orangefs.org, kexec@lists.infradead.org,
	linux-xfs@vger.kernel.org, bpf@vger.kernel.org,
	linux-perf-users@vger.kernel.org, kasan-dev@googlegroups.com,
	selinux@vger.kernel.org, alsa-devel@alsa-project.org,
	kernel-team@android.com
Subject: Re: [PATCH v2 4/6] mm: replace vma->vm_flags indirect modification
 in ksm_madvise
Message-ID: <Y9Fh9joU3vTCwYbX@dhcp22.suse.cz>
References: <20230125083851.27759-1-surenb@google.com>
 <20230125083851.27759-5-surenb@google.com>
 <Y9D4rWEsajV/WfNx@dhcp22.suse.cz>
 <CAJuCfpGd2eG0RSMte9OVgsRVWPo+Sj7+t8EOo8o_iKzZoh1MXA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAJuCfpGd2eG0RSMte9OVgsRVWPo+Sj7+t8EOo8o_iKzZoh1MXA@mail.gmail.com>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b="D/br1xSs";       spf=pass
 (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as
 permitted sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Michal Hocko <mhocko@suse.com>
Reply-To: Michal Hocko <mhocko@suse.com>
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

On Wed 25-01-23 08:57:48, Suren Baghdasaryan wrote:
> On Wed, Jan 25, 2023 at 1:38 AM 'Michal Hocko' via kernel-team
> <kernel-team@android.com> wrote:
> >
> > On Wed 25-01-23 00:38:49, Suren Baghdasaryan wrote:
> > > Replace indirect modifications to vma->vm_flags with calls to modifier
> > > functions to be able to track flag changes and to keep vma locking
> > > correctness. Add a BUG_ON check in ksm_madvise() to catch indirect
> > > vm_flags modification attempts.
> >
> > Those BUG_ONs scream to much IMHO. KSM is an MM internal code so I
> > gueess we should be willing to trust it.
> 
> Yes, but I really want to prevent an indirect misuse since it was not
> easy to find these. If you feel strongly about it I will remove them
> or if you have a better suggestion I'm all for it.

You can avoid that by making flags inaccesible directly, right?

-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y9Fh9joU3vTCwYbX%40dhcp22.suse.cz.
