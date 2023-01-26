Return-Path: <kasan-dev+bncBD6P7NUN4QMRBX7GZKPAMGQE7VZ6U5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id C715B67D292
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jan 2023 18:07:44 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 9-20020a05600c228900b003daf72fc827sf1334897wmf.9
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jan 2023 09:07:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674752864; cv=pass;
        d=google.com; s=arc-20160816;
        b=CaMEWNLQA+0hgwqhjl2CInVEE+FjPE9h8b4GzsAsbh6iT2xsdqwIUFq+pdynC5JcV3
         VNxLZvueZgfH+W2HtMnB2pD4xIlWkcnVOxfMaHKzkGwZUVnLriik8bT7i3HxezLBQkCp
         Wu2Rn754l1V/uY/HMOEFj7gwSMPkjRnZUkknNqN0y02VkpX6RyAGNauROj8Q3e4J2hys
         u3RzteIPuP4WZM3zKmdxbXUlC5h6wwkJCXfld0SuYDUBEiFo2t7IK/XbhsmIAkPkN2KG
         TQmQ5phmWSTCKTjXkCPd8LB5LkyY6Pr5VtI3shHOQxCm4BaW/BesArklYe9BFkHM4q76
         lFGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=2yEBhjaYj7i3N1lRM0ey84EfVEDDV/M0iYtle/hiSN0=;
        b=lGdcmqwToG6fHAgE0oN3vtNQ8hyW7da05+a7AK2EVGG+beobpqNFB8GTuhTNVdulch
         OBxFEYD4j68G+TpOyG3+DXNQrzT49PJU6HonXp3pV4YECN3DLVSLdn4xdBnDGHJCrc/9
         Hg3Gs6/HQk+bYmRfBfMvoNZB8k2vyaJaexJn/mt9ThTy2ggH5sytl+lXr1amDaBHMW7R
         Y45GVjEbByz+EjSPu3h5SBwFp/3jvE+PY1VZAdtg/ClC8QiMpS1ExyHGZKLnV9nV4nhk
         tT7guTklIxCpCd7rGGijD9PrE2VMNVu5o8rJSr6ALmTsP4IJWkzbHb10SPq33G+DHvL/
         rXqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@collabora.com header.s=mail header.b=HIAeawkS;
       spf=pass (google.com: domain of sebastian.reichel@collabora.com designates 46.235.227.172 as permitted sender) smtp.mailfrom=sebastian.reichel@collabora.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=collabora.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=2yEBhjaYj7i3N1lRM0ey84EfVEDDV/M0iYtle/hiSN0=;
        b=iNjRPx0qUWOzPc3+aFE6kI6tyxyHrORcwRYE37Bf+sbtuCJ3kiO/Vjm0ElsOWHMy5G
         qzJfOEKraX3CCu3zDfCr0yhSPiInzrRwglXZmByXBwEB/fwnwiGFwG1FVaTS6553Hs9L
         RsIWWmFexP03A5z8UBqkh9p8Ahn1vELc/HOoTKk6YUQWAx8Zi62Iwph9KtsZ0TeZaTi4
         fPjjIsL6OYZdygApgKF7OjJe//agfHC4Nnirj/wHoDXvBrpFHhHwy7EqQWUnmk0DruEO
         YsdWyQl6zClnhsihyCT5iLWKDsRa1NfEUMSSyU1zrcK22yU/43B7PZScPdcdt7uHyuic
         i7sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2yEBhjaYj7i3N1lRM0ey84EfVEDDV/M0iYtle/hiSN0=;
        b=7POp6lKEU2zynpskeaF3V2HOm5yB4aOKSp26hiGswGpK33JTmW5XiukPdE5pivuAWZ
         c9uPOvZRfzJYYeFRcHWS3Ex83/rBKT80Nk/WAyvb/i4gVJeat/UrOzh9G/AEDmK9LHRw
         nrSDq67luh81TYq1z9YGFue/13awkRSPRhdAo2DGVnUMt2tlzMVHsRxoa/JtzfggfqQt
         WUOCkzvqgIeWqDw1iGPSAAzbpmHNt5/ENcV5LBto8oVYDfE5te+/QQeM6AEstkDvHdDi
         bPZpgQt3ayDf+HE290wmEZVBHONKcQ8paKtdOxamm9v48Ky2/8q6c++DD5wdFj7K8TBO
         KumQ==
X-Gm-Message-State: AFqh2kp2Va7w9WHyRPsAipuyrGGIu1gKywbPvIcAyBOgKq3MSQ5VlJK8
	J+o0X2iszxD/94UYBKSQ8Io=
X-Google-Smtp-Source: AMrXdXsPAAi7+7Gs16P4Jz/OB6xW6xebkfqqtNSqv+nea+L02cPxvYE9mnmOj6j0KpeqVah8N3CYPQ==
X-Received: by 2002:a05:600c:5567:b0:3d0:5160:c81b with SMTP id ja7-20020a05600c556700b003d05160c81bmr2442616wmb.110.1674752864168;
        Thu, 26 Jan 2023 09:07:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3d06:b0:3cf:9be3:73dd with SMTP id
 bh6-20020a05600c3d0600b003cf9be373ddls3277766wmb.3.-pod-canary-gmail; Thu, 26
 Jan 2023 09:07:43 -0800 (PST)
X-Received: by 2002:a05:600c:34d1:b0:3db:1637:e415 with SMTP id d17-20020a05600c34d100b003db1637e415mr32396855wmq.22.1674752862929;
        Thu, 26 Jan 2023 09:07:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674752862; cv=none;
        d=google.com; s=arc-20160816;
        b=cPWPyk0MAVj5CJp03DFAelhZ7KOM/Y3j137tMK66vZ7mG5ksvfaccqY+svpdKgepGc
         y+Dcyf/OZarihw5RytpN12cOhWhhy/BKT9RHnNqka2EvPT+r4gfChYoncollvAsDGakv
         4KKAcCroKGHHKx/mj+tG0y6XVHnO6+5xMCgSsj6bKJrDgjP30qqkjojAIJVkk8hdaKJf
         I9OIDzzn607OJ1krGhQFjYDq/mZkIqyTmdpOuFXqAbgmKKorR4ST7c7JIpZ+IEAxaiEE
         Zs5x01zlNh/p2W4XLn5Hi0drzeLgSZMR35gN+alXDHQOPYQBTHmEWzAKohLtPaobfMFd
         wiPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=V5AwdQZIRoEI5EmbcWXk/1+v+KhF8j45S0wTnUUnZOE=;
        b=L4cKPAGtUzV10VWmW+cFdAazKSlz/aODS3r8PhdXlR6BoG/mGDNTg+CFo+Vw/O7HTJ
         aWxCJKXkRGQyVdSOhq1/CTF6YIJPeZ8Bd9TSrv9x+P7e+pTf40oja8kC0nKXci7muthu
         clIrvzyyYqRi+NLpz9U1TD9wDlHzScZaRLj0l1f1MBvvfmmJYuEe/hTU1yBBbVScBod8
         t9u4nCkMTB6KTsF+XtHhH0r8rDXrYu+3W/YnDNkGlLZwBzIKtn4AmjIJXNVnuBr9e/zS
         LkET2D7bOw/qxsv9d5IWqcrY52vmxB6+25u53olYz4QTQqPSQXyev0NTKaH3X8z/qsdR
         wBSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@collabora.com header.s=mail header.b=HIAeawkS;
       spf=pass (google.com: domain of sebastian.reichel@collabora.com designates 46.235.227.172 as permitted sender) smtp.mailfrom=sebastian.reichel@collabora.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=collabora.com
Received: from madras.collabora.co.uk (madras.collabora.co.uk. [46.235.227.172])
        by gmr-mx.google.com with ESMTPS id e15-20020a05600c4e4f00b003da0515e72csi373342wmq.2.2023.01.26.09.07.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Jan 2023 09:07:42 -0800 (PST)
Received-SPF: pass (google.com: domain of sebastian.reichel@collabora.com designates 46.235.227.172 as permitted sender) client-ip=46.235.227.172;
Received: from mercury (dyndsl-037-138-191-219.ewe-ip-backbone.de [37.138.191.219])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: sre)
	by madras.collabora.co.uk (Postfix) with ESMTPSA id 7E2906602E6E;
	Thu, 26 Jan 2023 17:07:41 +0000 (GMT)
Received: by mercury (Postfix, from userid 1000)
	id 8DAD710609C7; Thu, 26 Jan 2023 18:07:39 +0100 (CET)
Date: Thu, 26 Jan 2023 18:07:39 +0100
From: "'Sebastian Reichel' via kasan-dev" <kasan-dev@googlegroups.com>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, michel@lespinasse.org, jglisse@google.com,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	mgorman@techsingularity.net, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, peterz@infradead.org,
	ldufour@linux.ibm.com, paulmck@kernel.org, luto@kernel.org,
	songliubraving@fb.com, peterx@redhat.com, david@redhat.com,
	dhowells@redhat.com, hughd@google.com, bigeasy@linutronix.de,
	kent.overstreet@linux.dev, punit.agrawal@bytedance.com,
	lstoakes@gmail.com, peterjung1337@gmail.com, rientjes@google.com,
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
	ray.huang@amd.com, kraxel@redhat.com, mcoquelin.stm32@gmail.com,
	alexandre.torgue@foss.st.com, tfiga@chromium.org,
	m.szyprowski@samsung.com, mchehab@kernel.org,
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
Message-ID: <20230126170739.mlka2jivn3mfstyf@mercury.elektranox.org>
References: <20230125083851.27759-1-surenb@google.com>
 <20230125083851.27759-4-surenb@google.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="qcyccrleajamxo75"
Content-Disposition: inline
In-Reply-To: <20230125083851.27759-4-surenb@google.com>
X-Original-Sender: sebastian.reichel@collabora.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@collabora.com header.s=mail header.b=HIAeawkS;       spf=pass
 (google.com: domain of sebastian.reichel@collabora.com designates
 46.235.227.172 as permitted sender) smtp.mailfrom=sebastian.reichel@collabora.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=collabora.com
X-Original-From: Sebastian Reichel <sebastian.reichel@collabora.com>
Reply-To: Sebastian Reichel <sebastian.reichel@collabora.com>
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


--qcyccrleajamxo75
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

Hi,

On Wed, Jan 25, 2023 at 12:38:48AM -0800, Suren Baghdasaryan wrote:
> Replace direct modifications to vma->vm_flags with calls to modifier
> functions to be able to track flag changes and to keep vma locking
> correctness.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> ---
> [...]
>  drivers/hsi/clients/cmt_speech.c                   |  2 +-
>  120 files changed, 188 insertions(+), 199 deletions(-)
> [...]
> diff --git a/drivers/hsi/clients/cmt_speech.c b/drivers/hsi/clients/cmt_speech.c
> index 8069f795c864..952a31e742a1 100644
> --- a/drivers/hsi/clients/cmt_speech.c
> +++ b/drivers/hsi/clients/cmt_speech.c
> @@ -1264,7 +1264,7 @@ static int cs_char_mmap(struct file *file, struct vm_area_struct *vma)
>  	if (vma_pages(vma) != 1)
>  		return -EINVAL;
>  
> -	vma->vm_flags |= VM_IO | VM_DONTDUMP | VM_DONTEXPAND;
> +	set_vm_flags(vma, VM_IO | VM_DONTDUMP | VM_DONTEXPAND);
>  	vma->vm_ops = &cs_char_vm_ops;
>  	vma->vm_private_data = file->private_data;
>  

Acked-by: Sebastian Reichel <sebastian.reichel@collabora.com>

-- Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230126170739.mlka2jivn3mfstyf%40mercury.elektranox.org.

--qcyccrleajamxo75
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEE72YNB0Y/i3JqeVQT2O7X88g7+poFAmPSs1EACgkQ2O7X88g7
+pquLBAAkw9lw9lxNRCI6jvqLy98JsUBgSQigNB6Eh8JVWsySHMm1OszFCcvTpoc
vinC/VPMOa6JwEw5e9naXRF2UJahO+Cx+e5MYIKos3QyIUPfi0YM7Cv96h6+c4l/
NdcxLS8+9ElitTuA47UVgPSeZwzdZ1kU5VUV1X2fx+6aGA+dBfWVBgWDqU6AB0Sa
ehU4betso5Ypl26YEmLPHmY+8Xx2jXNwwBEgsHgO2/YjRn9YPDeMAqb4lWs99h0d
nUV1VqwTClRrExtNDvidHryknmyCIBpYt38gn0i9+uIf9mFoBmUDN+/zAdRguGBT
r1CQAwvRvHmEyGJ4dp1nijyt/PWxDBlCWytlmzXrK/rkeH8sQCRdCr9L83/d5DM0
iU98ehmbH9kx8rD4y0L91xmsnegNYNKSfAvz3EP4KYFOHjTw2SOCYoazPu3z62bN
d3HL+08LeZpm1XwVPydZqBd5UpBK8NaQYCJ3BjsLUefsSJE+SWzsnoYFnbUrL1X9
1XfU6LGtVvjCPUsjk7oqh5PjtRGQsdtUhSZJLwNzTeh4I0nSzL1pj8vRFZ7UTcV4
RmFYsjBbKhja2fC13eM4tKzfx53harnHVNuUPw2aoLKshpkQaOTUqWBnRXtbJZkb
dSRKObxfPlHVI+awnfN6owpXF86Owew2+XJcXILOPxaBk8PI/Ns=
=/0TB
-----END PGP SIGNATURE-----

--qcyccrleajamxo75--
