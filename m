Return-Path: <kasan-dev+bncBCKMR55PYIGBBLHTYOPAMGQESEAVC2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id F085567AE73
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 10:43:08 +0100 (CET)
Received: by mail-ej1-x63c.google.com with SMTP id nc27-20020a1709071c1b00b0086dae705676sf11679727ejc.12
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 01:43:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674639788; cv=pass;
        d=google.com; s=arc-20160816;
        b=wBd5XdHAEUC0n5w3a3bezPs+ijCkEib05g/oC/J/AfGjeyw0Aj9RDb1zue1bCclCDY
         ePp/H2LoeO0jFcC4jvsAurFnyT9gGfcqHVlm/kWomkOSIv1GopFvRo7zP8MYsTuW4xCb
         jZr4O1vekv5kOrUE3U5Q+UitqeWzHZb25aZW7hqXNYPoOo6boec3FGGF5gAlo6khLCIV
         Vh90ksPCwdR+3zCeiO9BXMYq1MnwNt0NBNULP3A2Nbwb78irI7PZ7inydx8iE2en3CjX
         xO6RfzH8tDXLyUyuFXnCZKe2NDBqlYf88ZGW7jniIiKtewsoeWMwHuDZTN8xr3mQzX1n
         mNjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=2h1scTPtoL7liaOVkwg/vrPCqzoxX6VCihYLlaTox4g=;
        b=tbVr7GDIsGT5/SvLwgD59R6QH20/PI97/z3f8e6oiK9iESMJLbmk7RQOtFFh7FyBh7
         HFUZxZpFUlnNFnvSTxBZEPoUaWcO6vKKIhnG60r3c+KbYwUVntFidsZgi/gc0WKZXrPS
         iZPZ7Abt+yna1FfIkgsc8pmx4d4sUh7ReVIkFDyC8TJctXZrtEUWIcqBbU0NnH2ibOBV
         e6P3EIc7GG2dQv2y4sbpGQo6cbidhbjG22/czIQd7ph2njzNSLxJyBcwnvgmMo3f7QAk
         AUFHGMqOrkspSvA4O3ziGbb61PavCmno1ZQ71Z9MSOQgOrr4L64A2oEtdMMRdnev9Hzy
         wpPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=mZDjQNB1;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=2h1scTPtoL7liaOVkwg/vrPCqzoxX6VCihYLlaTox4g=;
        b=d17nPTy1xn7NQSPTPU6REV/CGfTgXalvCmOvq6G2i+/z/Vl+TWNen/tKA1TeKnEUzg
         SkeChp0Thsa0y7aiz3JHHo94BowMZFcGKIZRl9UYwPeYe89dMh5TP0TJLc3uHItIQp05
         PbsBOUYdJpQqMyAhdfMPER2m1BidyTEk6IAiiNILwvtMJYiK/V4mKAXASUEnlaOojKTt
         HKGv26f9V5YS6U5t/0pto4dWmK8YZr3B3IZZvXiswmIMRvbWnBQixUs7Smdddn9JwsAA
         KCm3/8ecQvm2VHFUtfdF1eNjj+T5pDNaCqUuO+mfWpcoedhxrrFSx1Y61rYWOEIa2/Bl
         pBWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2h1scTPtoL7liaOVkwg/vrPCqzoxX6VCihYLlaTox4g=;
        b=ezk12C5+hNPGvTuTHMBPyjVSADcHGp0vBFLId5bZ044TWgLAsaMgdEchBiHZD7zKiv
         oEXh9BZW/YIaPqQ/hsHlA2nUFTkyUKUWU0QjyRmdfWpDUT9X0fgGSjG2tA/qOcvWs9FB
         ImThb9gkQAHfQATRF5yeUoTsnZoVkQW3qIj1cFU6B9IBtH0HFbDAoNGY2BiHkQ5nzlSx
         Trfo2lzOgNKbxmz++zDzsJYMCGVWtwNIdX7SChQ9CCiNCj8M1VNjH40o3nclly0MKI1G
         IcN+PJTe8v+5btn4RQvGby69WGPA/7M4wN1uTlUiBdCh4xwIt4RjZcPXtAED1ZL7E0m5
         b5JA==
X-Gm-Message-State: AFqh2kpeF5RoauWlG8m3KBvNFLKN80NA443JulKP/SCO4gHIbzK3JKOE
	E6Sv68lLUbX1lZ5Z0l77acY=
X-Google-Smtp-Source: AMrXdXvgdml0xqg8zSegoa8m7y7deQeUOpWeFeH526F2xVCuGsd30NNLtLEpJCOijiBPFe0k7Z5Y6g==
X-Received: by 2002:a17:906:66d3:b0:872:4813:f5a5 with SMTP id k19-20020a17090666d300b008724813f5a5mr3016144ejp.6.1674639788713;
        Wed, 25 Jan 2023 01:43:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:270a:b0:49e:5b8c:71c4 with SMTP id
 y10-20020a056402270a00b0049e5b8c71c4ls3156186edd.3.-pod-prod-gmail; Wed, 25
 Jan 2023 01:43:07 -0800 (PST)
X-Received: by 2002:a05:6402:5023:b0:4a0:8b2c:2055 with SMTP id p35-20020a056402502300b004a08b2c2055mr5639458eda.8.1674639787272;
        Wed, 25 Jan 2023 01:43:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674639787; cv=none;
        d=google.com; s=arc-20160816;
        b=qtokys8+2IRaR7VvquC58CV4dREpLB2FCRINPgsRc+NVljYkt936eTkYsKVdMLU7Lc
         VtT4SD7JWK6XVIRU3LKOdF/cd+3jsENPm5xTcc9PAOh0oFqjcBkIGKb1NOznYdOXY9Ex
         VZicnuh9ivYxhbrG1pm0kBJvSQAGKmzFlyzL2ZCu/RdiRm0UZYiRrzByBYAT+oZVkAuq
         zF+jsfuFsQZ3vxOkFmHvLnKotCM3VpW0zuocbfr4ik1Xnm8xHEqi3ck10jHTFTpokffu
         gCSrE04dtLA40Sl4fGN8vEpQaEz3UlwqTmJ0L+cifIMi3vHuCsAE1RKspC1zE4LWGnKe
         nRsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=/H7fv8j3//amIhsuvsnszBORL7yxYM5gHjte1pGnd6k=;
        b=aajJjKMR4XbJn0NLilybLiWPk+I5n2zEMJNtbCIWVTHc0xP0RlLKnFR38oPEV5GBxn
         9D5f8iEJz+sYcqn91MHcEXjpv0V3oZI33YW2acxinC9N9XanQgee7BpOKMoB81s/uQiH
         t9ekjCEXhKN4PEgrWE5OpRzqSFsanSLvGsP+pZpv9sRS91+tC4LEocEdKkjVwvfBqcSS
         4sEzbCZ7mWD27dKRDJZxaKLDUOaWItcDEaLO/0B7GvPdMGqOzbJiEmd/yuy6HbUaWT3y
         8locHEOGjWw7l5seMOG3k+erz8T0JxbtRRZm88TI/uZZf7E3lfodRte0y69qkJ6+u1co
         U4Jg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=mZDjQNB1;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id cf8-20020a0564020b8800b0048ebe118a43si248250edb.1.2023.01.25.01.43.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jan 2023 01:43:07 -0800 (PST)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id E751921C7E;
	Wed, 25 Jan 2023 09:43:06 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 8FA761358F;
	Wed, 25 Jan 2023 09:43:06 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id usqPIqr50GPHIgAAMHmgww
	(envelope-from <mhocko@suse.com>); Wed, 25 Jan 2023 09:43:06 +0000
Date: Wed, 25 Jan 2023 10:43:05 +0100
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
Subject: Re: [PATCH v2 6/6] mm: export dump_mm()
Message-ID: <Y9D5qS02j/fPLP/6@dhcp22.suse.cz>
References: <20230125083851.27759-1-surenb@google.com>
 <20230125083851.27759-7-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230125083851.27759-7-surenb@google.com>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=mZDjQNB1;       spf=pass
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

On Wed 25-01-23 00:38:51, Suren Baghdasaryan wrote:
> mmap_assert_write_locked() is used in vm_flags modifiers. Because
> mmap_assert_write_locked() uses dump_mm() and vm_flags are sometimes
> modified from from inside a module, it's necessary to export
> dump_mm() function.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

Acked-by: Michal Hocko <mhocko@suse.com>

> ---
>  mm/debug.c | 1 +
>  1 file changed, 1 insertion(+)
> 
> diff --git a/mm/debug.c b/mm/debug.c
> index 9d3d893dc7f4..96d594e16292 100644
> --- a/mm/debug.c
> +++ b/mm/debug.c
> @@ -215,6 +215,7 @@ void dump_mm(const struct mm_struct *mm)
>  		mm->def_flags, &mm->def_flags
>  	);
>  }
> +EXPORT_SYMBOL(dump_mm);
>  
>  static bool page_init_poisoning __read_mostly = true;
>  
> -- 
> 2.39.1

-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y9D5qS02j/fPLP/6%40dhcp22.suse.cz.
