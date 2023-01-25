Return-Path: <kasan-dev+bncBCKMR55PYIGBBUHNYOPAMGQEFC4QSXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id C937E67ADE2
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 10:30:57 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id w2-20020a0565120b0200b004cfd8133992sf7849382lfu.11
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 01:30:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674639057; cv=pass;
        d=google.com; s=arc-20160816;
        b=YObZ7L5TQS6SAvEpfiUv0LoDk7sw548Otw6EqDZUzNV1yFN789CQFaMbd8kIoqb1rz
         f/1j/pLHEWGzuu7V8QTtnObxC1SAoWxrdwbziPzFxh0kT8j1CNbMMvhzaEu9gAn71gn3
         T2FfORHfK90VGblsxGy6cFKv+fzgL1+ID6/bxmHuvIfD2/5VxJrtTy61/c7+L1z7/jB1
         qHbxjtNGtsNv5SgIcRI0ZNFNvPVQMBlDIDn0sOdmyQEJWGIGCxY3BK1bY/GM7w2BQjyq
         F1VGgfYn4RA4g6szquIrDLNgz8s0tD8Ve7pQHin3Cekf7Xi+gP4ELJTD4NsgwV4Sjc1x
         4JiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=OejO8c1vVyTqdMzieQKzXelw8ynHFhj8S2CCZDjAcqM=;
        b=iQOMvyb5XMSR/uHnEWrgKuTzqfp1++nIDE7nJ2pFd5rLKrThzm10IdrA56X9j4tSqO
         BNVtUjUEZhjMLzixrFO9pi7J7H67BayZJVd4jPAfH8N8ldoPlFnxHM9FRziOoyGUyciW
         0Tl4zMooJg3qkE2GrLLKJXvN/hHXCKfiqhAVtExpBJeoHBcsESMPPXOKce1MJL1DW4Fp
         UyfY+dVteegzXvzAUIJ61JUGQSvXaJF4L48OkHl19I96WWD5/1sBbmZ1tPrearLCs9JY
         kdbq8e/KKM8yv0FAKbtsw3/UMEMAXea0lIZnduPZ/JzWG6djWzIgIJ5cQTaJ2ygH5kbY
         ankg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=Pij8ssoJ;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=OejO8c1vVyTqdMzieQKzXelw8ynHFhj8S2CCZDjAcqM=;
        b=cS0EyWw4SeQmw6ep2WvKkyUCa0JRJj+a4jQrSbvgl0gQr5kd56VQUiqkBpN2RoDKWT
         m9GertGph2wcuxFmIBfJ6DyINRzjtW5m+OQsTqAAw3DUbRvOu7JDY1xC4+9KOYKn44VE
         MQ2qE+8iihc0HNUDcgVd1DxhQ9T+WGptR+tS4fsBjuuw+VROTbJSU9WWchso7axBSiIr
         F0E/H5XOl1dOd5CvlbpR5qGHuMUkLPycTp1vdVp+7MxBBVLP3xwhc0T2QTcaoR2RqMSu
         xDTr5Icn++sEkx4UyiA4KWBZjBdH3emK2aZ4/Fu1IqTHtwTTNT0qu7Aq2hoteM7Yjkns
         HDWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OejO8c1vVyTqdMzieQKzXelw8ynHFhj8S2CCZDjAcqM=;
        b=v1DEZZjPizFI0LNbO6hgdoD38zBVsT1a3QuxfAl3dNgVP+2HhTKJogsKC2RhHz14k2
         PUsYsLnACdZj84oFxb/BY2AUKJXTQJLFTTahAk/GUa0hGRt7mZg4ZrSHIJM/WqhhhorA
         XxzwSYEwGShtyEsJNYCaJ0L3Oi8Y/kKVpU7rqWmoEZKKken1b3VH2szEvi/RQ5xSjCEs
         PCDqWxN40FRuB5uqFJYwnrkUprFvdbNFvqE8ugzAh/s5pYxGxxfCZqQutu+rPO1Td+kA
         uhVcI4A5GS43/6Qhiiw5CdSroNK+gID4XEuEKP+e9UfviQ+AeA36igLrcc3E/2e68tXm
         US5g==
X-Gm-Message-State: AFqh2kq+LtKvF0emGVE91YV6LBrKVaArxfP4pkKHahMmuKVZFQxNAkDJ
	w0Nb+cnjphBv4ChIv4uT3iU=
X-Google-Smtp-Source: AMrXdXv91HUk95qIxKZy0e9B9wiRn0F0K8nM5tmUFhmVG6mX9yZRwjg4rMlpJQvJb/XRoOewmeaIXA==
X-Received: by 2002:ac2:4ac5:0:b0:4af:cd2:f8d5 with SMTP id m5-20020ac24ac5000000b004af0cd2f8d5mr2029048lfp.489.1674639057062;
        Wed, 25 Jan 2023 01:30:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:214f:b0:4c8:8384:83f3 with SMTP id
 s15-20020a056512214f00b004c8838483f3ls9053966lfr.3.-pod-prod-gmail; Wed, 25
 Jan 2023 01:30:55 -0800 (PST)
X-Received: by 2002:ac2:5a43:0:b0:4d0:ccbb:c3db with SMTP id r3-20020ac25a43000000b004d0ccbbc3dbmr7925815lfn.3.1674639055554;
        Wed, 25 Jan 2023 01:30:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674639055; cv=none;
        d=google.com; s=arc-20160816;
        b=QrWYv20ilsjNOzoUH6Gkf+k0ik4JxRMsjTz/aYxs5+07i7hnKqa/t2vwuGDFDswz3X
         aNAD6PqmBgssUy4XCAWMXPRtTAsd2W/WLWrnKjUJbUwDip4BUpKbs3e0/0kkqpUzqTBa
         304u7N/9jzQPt76Z1TMvUm7DV+63dKkCwGGrBnCc+f2PVpY9hIIQYNUThcMlRCpWB/v+
         LZpyi4rxaKZJ7n8uzAHuH8JOUmr1Fqk6RMyCahR5Q6RCCazm/T53JQW7+jSzJe/LYAXv
         xqUv1HtX8PY5ddFNoitKXuyX2Ff+y+eNc9HHLxC/BsMXW4vv4XSh3AqDoKv1spsDtAR6
         lLtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=jognpwZWDP/caNk47/2I5pB+VrjaxgWmcyaDbH1onsg=;
        b=llk+7WiOCPxKgUqozNoo9tfPI7EHKU7V+N5CgfQIGtRCIOTkmXOtIBJ6zkb59l16v7
         sEb4smBnAG94Nu+THVbcKoqeH0UKxRfFEpWLylk6qiYI9g9jTCtPfTf5XWXOVFE7jAP9
         1sOIgJ8NTEvHRipcFGEW4CSq+6Y5xdCmxHxNjKayknU5Pvkhz9Zzw1EPAWhk2RRK8CyM
         pIO/uVOy2KnOblxlkchGhPEFFuIkJeDVvLzSN1bayg6Fx7NFvP6hZoFw9CCNf+bV5vvr
         T+tzK8fGFfArg5yjgTjQ3KHhPFNjtiBIN9no1T81j4rcJwx/JUSa0p8P5lUmy2mS9s1D
         9DlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=Pij8ssoJ;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id t18-20020ac243b2000000b00492ce810d43si259146lfl.10.2023.01.25.01.30.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jan 2023 01:30:55 -0800 (PST)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id B91A621C63;
	Wed, 25 Jan 2023 09:30:54 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 684E91358F;
	Wed, 25 Jan 2023 09:30:54 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id yJRSGc720GMeHAAAMHmgww
	(envelope-from <mhocko@suse.com>); Wed, 25 Jan 2023 09:30:54 +0000
Date: Wed, 25 Jan 2023 10:30:53 +0100
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
Subject: Re: [PATCH v2 3/6] mm: replace vma->vm_flags direct modifications
 with modifier calls
Message-ID: <Y9D2zXpy+9iyZNun@dhcp22.suse.cz>
References: <20230125083851.27759-1-surenb@google.com>
 <20230125083851.27759-4-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230125083851.27759-4-surenb@google.com>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=Pij8ssoJ;       spf=pass
 (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted
 sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=suse.com
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

On Wed 25-01-23 00:38:48, Suren Baghdasaryan wrote:
> Replace direct modifications to vma->vm_flags with calls to modifier
> functions to be able to track flag changes and to keep vma locking
> correctness.

Is this a manual (git grep) based work or have you used Coccinele for
the patch generation?

My potentially incomplete check
$ git grep ">[[:space:]]*vm_flags[[:space:]]*[&|^]="

shows that nothing should be left after this. There is still quite a lot
of direct checks of the flags (more than 600). Maybe it would be good to
make flags accessible only via accessors which would also prevent any
future direct setting of those flags in uncontrolled way as well.

Anyway
Acked-by: Michal Hocko <mhocko@suse.com>
-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y9D2zXpy%2B9iyZNun%40dhcp22.suse.cz.
