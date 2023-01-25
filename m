Return-Path: <kasan-dev+bncBCKMR55PYIGBBMPRYOPAMGQE47CHNJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3461367AE20
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 10:38:58 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id d2-20020a0565123d0200b004d1b23f2047sf7955928lfv.20
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 01:38:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674639537; cv=pass;
        d=google.com; s=arc-20160816;
        b=v6jOIrjtXSsBiqUYXzhVnKrhS0lTy4vSoHgaifnmllAEQXdrR9VuFQz1UMaZeDyaU1
         3dt/vlqGIboPqfKw/x6x7eTDrg94AFSLapYMDn3v2m7KtgSuDfkAqWaMiPGxyYCwsEZ9
         SEN5co0CaLvPAFz4ELm6XeeNAnKmc/IzUDzwpMZ1fkZK9sVTyeSJ5T81msQ2An3tehjm
         xPBcDtA3y72CEmacw/mjlcZ0YoXaNgcgSdFeQW/3cay1BU37MjvHfqBiSdMnHqRhfEQC
         lsDGojGLJAzQOHDI/eSVO9DbnMPSiM8Gys3yq1wiVPB404rJCjxMmejT2q8Gxc1Ae7Me
         1XGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Nln9Y3HR/1iCFI3Z3t5fJhuBXVDw7j1UrS3IRGk4b5U=;
        b=g/1G3BFoHZ4z+JAocneAyLJnLHwrAzCO2dvfHZlbdXXkKNfECUsoL6dmkLCLlT9aMR
         zriLxvNPPv8Yoy5oe1WQKn66/lCE7OoYsOa7l9Q5R0JlVDjE2WizEhgEz8DF2NCdmTsX
         OY1Fojd6PlxVBT/Js5uaRExrqup+rDzQ2doHV3Q7/oHsHZn5dWpKtZJClM3oKHmuBsoP
         a+xyCFD4UyXTFGDGqKbeuhbfOs75Ani7+9g5uQezJQRKTvHcutOIk06tZo7SgW32DW9c
         PgSldSSB1+u1lhy6l1OUa3ml3x8QClBfzGnwxxSQmoopV+J48U3uJ7ItPdLgbgZyqAoV
         xqdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=r0FIat4k;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Nln9Y3HR/1iCFI3Z3t5fJhuBXVDw7j1UrS3IRGk4b5U=;
        b=C8NPDZGNZsMo/3jyJBORLQOSPShxLSOc13ZKzVQXVGslIHYC5OmV/GkbPyI3+K9is+
         1IFoZCdkRGGd2loL/nfU+3OkfX2VW/AyXyCUL3H9BRy9d38iRRKt926xRqB0NhsBEE7P
         ZCgFLPtJ1UewP3yfmWDBrhVHD9o29Lj93m+wbYOSssq+jdwT0OoDFmFUD9wzbiJTA+Lx
         S2kxL2SgnISajl4AYcWgdBnPnkpjZmBB8TjeVTW2IFv0oSq/sR1Q/d0CfHgrygmzmZLs
         1oztLf3jdzAvEgKPvd/R5mZcH8uKqmyMxWocdwAdS6dxOQQU2yx0fg5vD7r9TY7M9k8X
         7pRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Nln9Y3HR/1iCFI3Z3t5fJhuBXVDw7j1UrS3IRGk4b5U=;
        b=0OGRb10d4VwWtc0gM06ByHSaT/NYq6GzZuJ6LXrF34uoiiM3dlh59RTHYRC8DICiK+
         WWf8/QbRXTOdasRwHHlyE7McR99bbTM5CLLK5g4NuHvOw6bvxcRgD9ue4mym/P/NTvwT
         1+hrJ0w/EndoAIg9L18nLrcmgUK/bhuyAoQAcquSP3fAlM032c6L0cUVdkQY91QkRqCl
         V4N1RUYDuxFDlPYnE98Ew7FiaysUNsd7OKaQNrPGGSn7n1p2y7FgAxgd48GQnWLN/09E
         YgSM7NK0dy0Z1iGxzbOumh2xi11nbfJDdMV1cdATd6p3dknblndZiatdSEgQa/f4Pj5R
         Revw==
X-Gm-Message-State: AFqh2ko2qN1G8Ygwu9br8Es6JueOm/1LegwKXEbSuvpD6E2SaMNXDFtg
	28qeZ9FsWrUSb+cBxy9WGuw=
X-Google-Smtp-Source: AMrXdXvw2RMf8EAmjTla7Mk61ofVK5PORSpVOaJEI0Prh3TT/xB4pyD5mB2cIUJIECmZvkZ50ktzkQ==
X-Received: by 2002:a05:6512:23a2:b0:4cb:3bd2:2ea2 with SMTP id c34-20020a05651223a200b004cb3bd22ea2mr1642592lfv.594.1674639537649;
        Wed, 25 Jan 2023 01:38:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a413:0:b0:27f:e5b1:aff6 with SMTP id p19-20020a2ea413000000b0027fe5b1aff6ls2437677ljn.6.-pod-prod-gmail;
 Wed, 25 Jan 2023 01:38:56 -0800 (PST)
X-Received: by 2002:a05:651c:1a29:b0:279:ee72:6ab1 with SMTP id by41-20020a05651c1a2900b00279ee726ab1mr10714996ljb.42.1674639535991;
        Wed, 25 Jan 2023 01:38:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674639535; cv=none;
        d=google.com; s=arc-20160816;
        b=UyPeHzw10sSpah+Npv3AMpMyGXfov/j8ivtFMqjMcr3swUNOdTXwqvOGV1FpLp5umq
         TMl8N3sDLClhAb37eIcN5pvf8vu7BYuHkjRBQRFYflQZM5zpxzD/1C8XlD4nawA5UA1x
         DJ5cYpo5CzM8vZWwxl9AmrInNK0oRzkfhoM5XBMFcl5iq/CdoIzx3+MJsDJL4/jvGmFZ
         +T0A1AyirpUydRQitz0KdyLR/lyzFBEKSi369iUptDtzg0X2nirhm7U/fi9e+/DoBt9H
         /dcnOlaibN3FxDkMivYJHl3G75DlT0d3DvwkElYNr/nvmFs8B8ghn6Rb+bKPWhlFAlIl
         k8aA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=rlC3v8G7Qltb7/sMWGykfElAbj3RZvreU88MtZ+OLHM=;
        b=ETTcgAkssYyFgy5bJBOn5VI5ZBowVZzIKt8sv7u8qyuh7pLV3Eh53iy7Ppp2GDzDKE
         V9uKVZ/jW8or+1sED4e0vUkhv4tJh6NvvFLU8zJiyWJtbgrsKfJRGv2jcEZpBV3gzwKT
         0bXGsoECDAk2UeJzNRHBcZkqL2AQDN6w65ZL9RZ0PIVnZnXwvdzgKMkRDoABXf0wparz
         KpgTWogG9FRwCXH1Yk6SeV0mZgQfxi0S44HUHIZ9luMdAm9CgHZd/BE0mvcfd7PLaLaF
         jAhk3z0AWKEE3FHwCybshB1j2h/Gext+ogWEI0Fb1srQD8nnhj3+QYJPjYCf4vPD6F6X
         MZtw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=r0FIat4k;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id x27-20020a2ea99b000000b0028b731e8e20si217130ljq.1.2023.01.25.01.38.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jan 2023 01:38:55 -0800 (PST)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 94D5721C7F;
	Wed, 25 Jan 2023 09:38:54 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 446411358F;
	Wed, 25 Jan 2023 09:38:54 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id jLUjEK740GMsIAAAMHmgww
	(envelope-from <mhocko@suse.com>); Wed, 25 Jan 2023 09:38:54 +0000
Date: Wed, 25 Jan 2023 10:38:53 +0100
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
Message-ID: <Y9D4rWEsajV/WfNx@dhcp22.suse.cz>
References: <20230125083851.27759-1-surenb@google.com>
 <20230125083851.27759-5-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230125083851.27759-5-surenb@google.com>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=r0FIat4k;       spf=pass
 (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as
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

On Wed 25-01-23 00:38:49, Suren Baghdasaryan wrote:
> Replace indirect modifications to vma->vm_flags with calls to modifier
> functions to be able to track flag changes and to keep vma locking
> correctness. Add a BUG_ON check in ksm_madvise() to catch indirect
> vm_flags modification attempts.

Those BUG_ONs scream to much IMHO. KSM is an MM internal code so I
gueess we should be willing to trust it.

> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

Acked-by: Michal Hocko <mhocko@suse.com>
-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y9D4rWEsajV/WfNx%40dhcp22.suse.cz.
