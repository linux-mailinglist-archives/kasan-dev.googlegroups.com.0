Return-Path: <kasan-dev+bncBDQ2L75W5QGBBR735OKQMGQEE32YZCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 23FA655D234
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 15:10:33 +0200 (CEST)
Received: by mail-oi1-x23b.google.com with SMTP id w1-20020aca3001000000b00335750b9a50sf3129125oiw.10
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 06:10:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656421832; cv=pass;
        d=google.com; s=arc-20160816;
        b=HPEr+Ez3C2Yeu3WmIpv5b8GhoPD9VVnwug9dgW5gSd/VkTADv+krNkWLh9GlKKvpxM
         vTvNClLEb1nCfg2324QdBnqlCd1IZdllUHWm9bWt71TDpCsCbr8iFOn4zW3TpK6vPHIm
         fLY5zxdH4mkVWl8YMrxu7MwT2HhnAwG6rEURIoukXT+wNMXWzTcyPDGJJuRVIHdTPwnj
         0LdLOaOO+bpAn51PgvAEC90wlYHLAADxlt8POaql9CBwEBAaL3AqNoU4bYMW0sm0qIG2
         gEHtwoikgmucMmipndZv6bFBL3vRJr1sbFOzv2d7VPxDjfWBRmtEvX7h2GDRgLWS7WUv
         sy5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:date:message-id
         :subject:references:in-reply-to:cc:to:from:sender:dkim-signature;
        bh=q8nhHbIAwfWyn59wAdOzrmBTa5vKV8DMfNQGrB+XcpU=;
        b=D+lNGpxzE7ElWyNdbOCDSahy8TsRoT/KbUaq1z/oVVYndOr7FAZmf6+cHQot0AcIac
         FTp2M2IOlJbwl99l3esrmygs+fed9k9usXaoWhphC7LFc7wFa7PmXqFsfEm5ORPaU+2Q
         0BsAG3fe69VNAWdjV3QX/gTEwhj9Nu0xsz/vDbIARqWwm/C8GHqMAi+Kq/EYkyP/ZGqI
         kU0RQgtepPo1iVh4hAFqCcbGP1NpkSVKcCn8Md/XLoXogvvX7SHGJXNGabbH2kBWeEgT
         b6f7P/vMvurjiCSt7wm7YMtXL6ttP1DLv6nekE6dSAl4wzvytYU+4ytzE07mgW6FwUf5
         IjNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=fail header.i=@kernel.org header.s=k20201202 header.b="lZBjp0/a";
       spf=pass (google.com: domain of broonie@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=broonie@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:in-reply-to:references:subject:message-id:date
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q8nhHbIAwfWyn59wAdOzrmBTa5vKV8DMfNQGrB+XcpU=;
        b=oNVeyZrjCGqE3Zz7dgqW/NouQ5o85Lv1VFpHmXd/MXOTKiaNNyOLXiy7l49vMHDVz3
         5SiegPD/f5Bzm4l8uoYGiMHF9L2er8Gedx/WMoHAiL0ano6vhlBtMEJmjvgX1ZSYZfdS
         avM4ZsL6RdgySt0j7qKoAKWRL9iTEjQy9Dn4oydLH8Ntd7pF9MCnMFt7ir3wjru/Cg2o
         tjsKvat3sjnOggZiyyhXVZ307PeaEn9eOi+4/OzMMna13FIIByGL3Jt+827Ku5m+lppk
         FVyyf8MBLp7HlJTwgDRkgXReB0o8QzksvD1gT0xQN2FEpPGg7QqrTcBUoopLN+R+Ukoe
         hkgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:in-reply-to:references:subject
         :message-id:date:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q8nhHbIAwfWyn59wAdOzrmBTa5vKV8DMfNQGrB+XcpU=;
        b=7MXeqoqHVguWfLwuvCGaRhKd96D7Y6ilu3n7L9YgWH0tz8S+bBEb3I72R7Efd81M8D
         mHkKlOgOxJO/R4Rr0QTt6aR/JmRPyRU79TsFS6K/6Vvf397NtYTI56gUea26svlbaU0V
         HwEWmJLrW/70rSKn6Ua5sAQGOlMGq9jKBXgSZvKbQttfztxDY8GoVlYnF/K66CbmTlr/
         Jqgk34XfRVOKBSKPTwSBMnkEl+MOgVWFeAPJ+sHXAUz6smkGoaL5GSiuj4vUck+0y1Cr
         zNpNlK1DUDI1WrAIjrEvNTxKZ3k4Y71IUySos5Ak74RDDfOoNvd102zmeWUnl6MzXA7p
         5lyA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/P3+lVMlTxvoQJ2dxmumCHUobIBpZpMq4jjZr1cduPsxHLucnp
	0RS+4f8+iFvxmhi3RdqNmNQ=
X-Google-Smtp-Source: AGRyM1t8MbQIDu61QyhO6rCVZvKTA981NcEbRWFbKCr655SC+ihOo9VZNQ5Zyee6iX2qodBjUtEbXg==
X-Received: by 2002:a05:6808:1889:b0:32f:65e3:be98 with SMTP id bi9-20020a056808188900b0032f65e3be98mr13986130oib.160.1656421831884;
        Tue, 28 Jun 2022 06:10:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1b2a:b0:335:1841:b2c6 with SMTP id
 bx42-20020a0568081b2a00b003351841b2c6ls6446052oib.9.gmail; Tue, 28 Jun 2022
 06:10:31 -0700 (PDT)
X-Received: by 2002:aca:3b02:0:b0:335:2d22:dbf4 with SMTP id i2-20020aca3b02000000b003352d22dbf4mr12838309oia.185.1656421831375;
        Tue, 28 Jun 2022 06:10:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656421831; cv=none;
        d=google.com; s=arc-20160816;
        b=sFIH8PX2YERO5EkVFfuV7cCYmV4E8nXMUOGAZC5VmhgtPi7I65/ZrVJRC5pzhhZ0s5
         qEort2/PsPGPnKEQPqQtdkL7H3UHDqQ8efM261vBep1b49Koiu/QLg3Hv0MBdnVcfudI
         NBt8z0xSU2IEmKo0LjRW0i4YLuU5Bk3IcWzgwdgLX/w6Hv9cDv3gpAIYhv17LES5RTQL
         +ehSsxX8GM3xOMe6b8++t7VtNDquU/YGtNz5gCjXilHdGDt+aNdL/GJwahZf/F7sWibp
         YEMDrb3oxOfsYbAvGRNWo9ktObtBMRrrb3LskS/6g+qQ0fdD2uekroDnd8a9xAvCavRB
         wTnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:date:message-id:subject
         :references:in-reply-to:cc:to:from:dkim-signature;
        bh=wBxoUG0Lj09ekTXFxsIUOaAPUB4KUKIamPgSZFxhVu8=;
        b=M5C6axWg6zWYrWM04FUl7w7h3yQwwXRuHpC90IgITbnyIddUGAt+zw89a6wag725xy
         8Cai1UHAh3Uzatx63FoDqLngf19Tfy3NeGcNGPhLD4t7S2q7U9N2sFtmWGV8F2f7Y0zE
         TB+TkiI2xEjjUm9gZ/LABGG26fTB5D7lkCvt/QhhYxkoQ4Jtl66ghMI0Pj9IxfYhEzYl
         3/Lod9labiOh/3Yq6fyjgqVfOoo3GXoqy/wTo2MJZo9oUKO5YsRS2i57l51W+QhLGEQE
         Qac1lQvgtTuAaXjd7fNYAAUIfog7wfWX/OCG8c9oJt+Ooww71ztJfs4Yc71RN24zhrFb
         EVKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=fail header.i=@kernel.org header.s=k20201202 header.b="lZBjp0/a";
       spf=pass (google.com: domain of broonie@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=broonie@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id g5-20020a056870c14500b00101c9597c72si1808238oad.1.2022.06.28.06.10.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 28 Jun 2022 06:10:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of broonie@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 148126170D;
	Tue, 28 Jun 2022 13:10:31 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 86553C3411D;
	Tue, 28 Jun 2022 13:10:22 +0000 (UTC)
From: Mark Brown <broonie@kernel.org>
To: mchehab@kernel.org, linux-doc@vger.kernel.org
Cc: heikki.krogerus@linux.intel.com, daniel@ffwll.ch, mingo@redhat.com, bp@alien8.de, netdev@vger.kernel.org, pabeni@redhat.com, linux-fsdevel@vger.kernel.org, sumit.semwal@linaro.org, mchehab+huawei@kernel.org, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-pm@vger.kernel.org, christian.koenig@amd.com, airlied@linux.ie, corbet@lwn.net, hpa@zytor.com, linux-mm@kvack.org, linaro-mm-sig@lists.linaro.org, linux-media@vger.kernel.org, tglx@linutronix.de, myungjoo.ham@samsung.com, glider@google.com, balbi@kernel.org, davem@davemloft.net, johannes@sipsolutions.net, linux-cachefs@redhat.com, x86@kernel.org, dave.hansen@linux.intel.com, linux-wireless@vger.kernel.org, Al Viro <viro@zeniv.linux.org.uk>, kuba@kernel.org, dri-devel@lists.freedesktop.org, linux-sgx@vger.kernel.org, andrey.grodzovsky@amd.com, cw00.choi@samsung.com, dvyukov@google.com, elver@google.com, Andrew Morton <akpm@linux-foundation.org>, amd-gfx@lists.freedesktop.org, linux-usb@vger.kernel.org, edumazet@go
 ogle.com, kyungmin.park@samsung.com
In-Reply-To: <cover.1656409369.git.mchehab@kernel.org>
References: <cover.1656409369.git.mchehab@kernel.org>
Subject: Re: (subset) [PATCH 00/22] Fix kernel-doc warnings at linux-next
Message-Id: <165642182225.1205882.7217075149410531618.b4-ty@kernel.org>
Date: Tue, 28 Jun 2022 14:10:22 +0100
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: broonie@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=fail
 header.i=@kernel.org header.s=k20201202 header.b="lZBjp0/a";       spf=pass
 (google.com: domain of broonie@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=broonie@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, 28 Jun 2022 10:46:04 +0100, Mauro Carvalho Chehab wrote:
> As we're currently discussing about making kernel-doc issues fatal when
> CONFIG_WERROR is enable, let's fix all 60 kernel-doc warnings
> inside linux-next:
> 
> 	arch/x86/include/uapi/asm/sgx.h:19: warning: Enum value 'SGX_PAGE_MEASURE' not described in enum 'sgx_page_flags'
> 	arch/x86/include/uapi/asm/sgx.h:97: warning: Function parameter or member 'rdi' not described in 'sgx_enclave_user_handler_t'
> 	arch/x86/include/uapi/asm/sgx.h:97: warning: Function parameter or member 'rsi' not described in 'sgx_enclave_user_handler_t'
> 	arch/x86/include/uapi/asm/sgx.h:97: warning: Function parameter or member 'rdx' not described in 'sgx_enclave_user_handler_t'
> 	arch/x86/include/uapi/asm/sgx.h:97: warning: Function parameter or member 'rsp' not described in 'sgx_enclave_user_handler_t'
> 	arch/x86/include/uapi/asm/sgx.h:97: warning: Function parameter or member 'r8' not described in 'sgx_enclave_user_handler_t'
> 	arch/x86/include/uapi/asm/sgx.h:97: warning: Function parameter or member 'r9' not described in 'sgx_enclave_user_handler_t'
> 	arch/x86/include/uapi/asm/sgx.h:124: warning: Function parameter or member 'reserved' not described in 'sgx_enclave_run'
> 	drivers/devfreq/devfreq.c:707: warning: Function parameter or member 'val' not described in 'qos_min_notifier_call'
> 	drivers/devfreq/devfreq.c:707: warning: Function parameter or member 'ptr' not described in 'qos_min_notifier_call'
> 	drivers/devfreq/devfreq.c:717: warning: Function parameter or member 'val' not described in 'qos_max_notifier_call'
> 	drivers/devfreq/devfreq.c:717: warning: Function parameter or member 'ptr' not described in 'qos_max_notifier_call'
> 	drivers/gpu/drm/amd/amdgpu/amdgpu_device.c:5095: warning: expecting prototype for amdgpu_device_gpu_recover_imp(). Prototype was for amdgpu_device_gpu_recover() instead
> 	drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm.h:544: warning: Function parameter or member 'dmub_outbox_params' not described in 'amdgpu_display_manager'
> 	drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm.h:544: warning: Function parameter or member 'num_of_edps' not described in 'amdgpu_display_manager'
> 	drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm.h:544: warning: Function parameter or member 'disable_hpd_irq' not described in 'amdgpu_display_manager'
> 	drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm.h:544: warning: Function parameter or member 'dmub_aux_transfer_done' not described in 'amdgpu_display_manager'
> 	drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm.h:544: warning: Function parameter or member 'delayed_hpd_wq' not described in 'amdgpu_display_manager'
> 	drivers/gpu/drm/amd/include/amd_shared.h:224: warning: Enum value 'PP_GFX_DCS_MASK' not described in enum 'PP_FEATURE_MASK'
> 	drivers/gpu/drm/scheduler/sched_main.c:999: warning: Function parameter or member 'dev' not described in 'drm_sched_init'
> 	drivers/usb/dwc3/core.h:1328: warning: Function parameter or member 'async_callbacks' not described in 'dwc3'
> 	drivers/usb/dwc3/gadget.c:675: warning: Function parameter or member 'mult' not described in 'dwc3_gadget_calc_tx_fifo_size'
> 	fs/attr.c:36: warning: Function parameter or member 'ia_vfsuid' not described in 'chown_ok'
> 	fs/attr.c:36: warning: Excess function parameter 'uid' description in 'chown_ok'
> 	fs/attr.c:63: warning: Function parameter or member 'ia_vfsgid' not described in 'chgrp_ok'
> 	fs/attr.c:63: warning: Excess function parameter 'gid' description in 'chgrp_ok'
> 	fs/namei.c:649: warning: Function parameter or member 'mnt' not described in 'path_connected'
> 	fs/namei.c:649: warning: Function parameter or member 'dentry' not described in 'path_connected'
> 	fs/namei.c:1089: warning: Function parameter or member 'inode' not described in 'may_follow_link'
> 	include/drm/gpu_scheduler.h:463: warning: Function parameter or member 'dev' not described in 'drm_gpu_scheduler'
> 	include/linux/dcache.h:309: warning: expecting prototype for dget, dget_dlock(). Prototype was for dget_dlock() instead
> 	include/linux/fscache.h:270: warning: Function parameter or member 'cookie' not described in 'fscache_use_cookie'
> 	include/linux/fscache.h:270: warning: Excess function parameter 'object' description in 'fscache_use_cookie'
> 	include/linux/fscache.h:287: warning: Function parameter or member 'cookie' not described in 'fscache_unuse_cookie'
> 	include/linux/fscache.h:287: warning: Excess function parameter 'object' description in 'fscache_unuse_cookie'
> 	include/linux/genalloc.h:54: warning: Function parameter or member 'start_addr' not described in 'genpool_algo_t'
> 	include/linux/kfence.h:221: warning: Function parameter or member 'slab' not described in '__kfence_obj_info'
> 	include/linux/regulator/driver.h:434: warning: Function parameter or member 'n_ramp_values' not described in 'regulator_desc'
> 	include/linux/textsearch.h:51: warning: Function parameter or member 'list' not described in 'ts_ops'
> 	include/linux/usb/typec_altmode.h:132: warning: Function parameter or member 'altmode' not described in 'typec_altmode_get_orientation'
> 	include/net/cfg80211.h:391: warning: Function parameter or member 'bw' not described in 'ieee80211_eht_mcs_nss_supp'
> 	include/net/cfg80211.h:437: warning: Function parameter or member 'eht_cap' not described in 'ieee80211_sband_iftype_data'
> 	include/net/cfg80211.h:507: warning: Function parameter or member 's1g' not described in 'ieee80211_sta_s1g_cap'
> 	include/net/cfg80211.h:1390: warning: Function parameter or member 'counter_offset_beacon' not described in 'cfg80211_color_change_settings'
> 	include/net/cfg80211.h:1390: warning: Function parameter or member 'counter_offset_presp' not described in 'cfg80211_color_change_settings'
> 	include/net/cfg80211.h:1430: warning: Enum value 'STATION_PARAM_APPLY_STA_TXPOWER' not described in enum 'station_parameters_apply_mask'
> 	include/net/cfg80211.h:2195: warning: Function parameter or member 'dot11MeshConnectedToAuthServer' not described in 'mesh_config'
> 	include/net/cfg80211.h:2341: warning: Function parameter or member 'short_ssid' not described in 'cfg80211_scan_6ghz_params'
> 	include/net/cfg80211.h:3328: warning: Function parameter or member 'kck_len' not described in 'cfg80211_gtk_rekey_data'
> 	include/net/cfg80211.h:3698: warning: Function parameter or member 'ftm' not described in 'cfg80211_pmsr_result'
> 	include/net/cfg80211.h:3828: warning: Function parameter or member 'global_mcast_stypes' not described in 'mgmt_frame_regs'
> 	include/net/cfg80211.h:4977: warning: Function parameter or member 'ftm' not described in 'cfg80211_pmsr_capabilities'
> 	include/net/cfg80211.h:5742: warning: Function parameter or member 'u' not described in 'wireless_dev'
> 	include/net/cfg80211.h:5742: warning: Function parameter or member 'links' not described in 'wireless_dev'
> 	include/net/cfg80211.h:5742: warning: Function parameter or member 'valid_links' not described in 'wireless_dev'
> 	include/net/cfg80211.h:6076: warning: Function parameter or member 'is_amsdu' not described in 'ieee80211_data_to_8023_exthdr'
> 	include/net/cfg80211.h:6949: warning: Function parameter or member 'sig_dbm' not described in 'cfg80211_notify_new_peer_candidate'
> 	include/net/mac80211.h:6250: warning: Function parameter or member 'vif' not described in 'ieee80211_channel_switch_disconnect'
> 	mm/memory.c:1729: warning: Function parameter or member 'mt' not described in 'unmap_vmas'
> 	net/mac80211/sta_info.h:569: warning: Function parameter or member 'cur_max_bandwidth' not described in 'link_sta_info'
> 
> [...]

Applied to

   https://git.kernel.org/pub/scm/linux/kernel/git/broonie/regulator.git for-next

Thanks!

[18/22] regulator: fix a kernel-doc warning
        commit: 0e584d46218e3b9dc12a98e18e81a0cd3e0d5419

All being well this means that it will be integrated into the linux-next
tree (usually sometime in the next 24 hours) and sent to Linus during
the next merge window (or sooner if it is a bug fix), however if
problems are discovered then the patch may be dropped or reverted.

You may get further e-mails resulting from automated or manual testing
and review of the tree, please engage with people reporting problems and
send followup patches addressing any issues that are reported if needed.

If any updates are required or you are submitting further changes they
should be sent as incremental updates against current git, existing
patches will not be replaced.

Please add any relevant lists and maintainers to the CCs when replying
to this mail.

Thanks,
Mark

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/165642182225.1205882.7217075149410531618.b4-ty%40kernel.org.
