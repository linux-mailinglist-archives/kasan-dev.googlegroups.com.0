Return-Path: <kasan-dev+bncBDN3FGENWMIRB6M35OKQMGQEYXXKGXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4137C55BFD9
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 11:46:35 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id q36-20020a0c9127000000b00461e3828064sf11775026qvq.12
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 02:46:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656409594; cv=pass;
        d=google.com; s=arc-20160816;
        b=IcLTaEKM+jyRGc65Gqv0aLJuXLSfFhskWFZ/4hNtbVzJrOUC/PLIwpKoOStGjjlZkD
         vARJcpk5Zz3T41Ptg+fH2fbH6+W7VpchEu6KIFF4TzHzModxggiyDSJXsSZIv4pkfeMw
         /rIUuo6HhpRMndaiQxemB79lCu8oNEwvyp637UtckR1Qr5Iej0wasgZo9/D0k8TRM2yg
         FEa9HY21s31mCE+3kNzfq6CCp4cO9m1H342A7NIqvGe+o44YnBgy/XiRwRAwg1Ay9hZu
         D6oTYCrwQvqLHu8jDqhURRgYq+LwH/INgvF2dZJHoVbMbcJze0HftgmPmuMINLE70JTP
         Wo4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ZXtY1WYmQzKcfTS2ObEqTMLF6buajOA+UsKb5sLiKtU=;
        b=xu0I+U9p3A0OMgGTqwT4ga3g2K4LFYFIOMiLWZWzlL5amxZ/m9XXiwwaPlaZGN4yCN
         5U/LsDr6QNm/oRbu9IvCzx04myKPIlpAmVAhLsHmfjcwIQ8TbRmP8xFfdxGEYOTY1gNL
         Mywp9bN1RrBEZEudnlSgYkza6/rQWyi5Z10mzu0arvcauSyapsmJaMvbTTvXteAkrq8J
         zFnobs7kr6WBhSJcOGFRYIJgWoV5M4tfSO8iSSZCXPq5JAV5+9TvcbYY21xfeG6CJRXI
         gJ7dv5/h81YihjaEbqgE6FIYViCiza/eznBL4BvPPKvqIwmuR0dCKKAkRR14bslVd4qN
         PUeQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nOcRjaFP;
       spf=pass (google.com: domain of mchehab@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=mchehab@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZXtY1WYmQzKcfTS2ObEqTMLF6buajOA+UsKb5sLiKtU=;
        b=iFUC8CI7IGf0h+QlEfRoo4pwfLD9fOkcD9iynEZGaU18DE+bRiuLHPlB9Ft7t87rz/
         JMK50UMTcvHwxFs58UW2sKVojXISpYD+oomElGX4BJJrGn+/eQpBN1wFQBLei61frsmR
         4+vfxXj7fljzSRLv5paVydAxA9NCA1E1Lh5SumV7kxtA/k3gACLGcHCBOBE3LKCozhoi
         w1b2TnBkej/lklMX+mEjvPhXouUJBq/sUxwHv47WWLXqz4f5osODScSkQwxyqh/M2QUT
         w5wVg9lVYumakwDMCqc9b+z5/LCKZv7xnmdRrxnRscLZqfBYxM47tA5DSDkiYIb3b84i
         IhQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZXtY1WYmQzKcfTS2ObEqTMLF6buajOA+UsKb5sLiKtU=;
        b=2Ok+7SE8gbq7BgEL8sNIzMGwq81oiRWPOZZ8uDavJ88F3YkXFWaOlX/f5vOTLJaCHe
         1h7ZNzCjPV2YwYlf8XzmlgmGFVKeSrSyJfzipow2Zx6cZE578dplltJpMfEi5+Tofr++
         sEQrXsMBoI3zhnJIPOo3jBQD55/lj06WL4CU7KN2Qh+1PGo50JmRFOuQjqtgQlAX0r68
         1W0NLSmr6Z9C0FbsYPnER3nzIVdtyEk6l8MJ9xZMn22OaG6X4PQUlPR7Edol9ZtZgy5T
         SMMMRNfwTI6/0YmJuzCIvTU+os9+5l3+0pW8khGGdjFVSfWKdl2MVxsi1sygQqxGdkjO
         sDxQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora95L0lFfUTX0VacZQ7ZjCuAMEiO7awIFovK9FHAbfggfeBFHX+m
	79uiTgYS/b6vYOSEz1njhKM=
X-Google-Smtp-Source: AGRyM1uK7KqCCaD+HAfgpoezXrpTGbAGZsconYcV05G5pRx7bQEah2YKcW2wtxsPWLps5F8ZFGpcMA==
X-Received: by 2002:ac8:5bcf:0:b0:31b:ebe2:fee7 with SMTP id b15-20020ac85bcf000000b0031bebe2fee7mr2993026qtb.653.1656409593875;
        Tue, 28 Jun 2022 02:46:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:1925:b0:6af:1d31:f488 with SMTP id
 bj37-20020a05620a192500b006af1d31f488ls3538235qkb.6.gmail; Tue, 28 Jun 2022
 02:46:33 -0700 (PDT)
X-Received: by 2002:a05:620a:747:b0:6af:25b4:bb28 with SMTP id i7-20020a05620a074700b006af25b4bb28mr6253873qki.438.1656409593335;
        Tue, 28 Jun 2022 02:46:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656409593; cv=none;
        d=google.com; s=arc-20160816;
        b=t2Alffl4OdnydJ8FbYiAvAh6UneZbIWTxIyol5h4EjJhIbmj2SB5YdPglYAcLDtN1Q
         pjv8BPwPYlU0Ee8OijKHEEi5YhrGXDCeDFMsIMhqgcOG9brKo3Uso5e7P1SCVgxXZcpo
         MGo+Djy9YSZqGADEj62FRTzvWrVBDc4xTNwgEqBBZJq2+wIXNd0I8oKYQAI54AakT1N9
         D3f5ncqqKZhDdf7WrEmB5p10ulp2WEaJAzNe6+b9e+uz9UQuUXqsKZSc8L1zIUyyvzHw
         VuQibGybq5CLr4hytixATxABrvBCtzLE7aqJ9JBGOlt4cIh6GoRMjp3+bKL0hiRPsluR
         yt1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=spxa3XpKIfVUAdXgQ495jzOeOyEqJ3/tVkOU5VXIqJE=;
        b=HsNclyQJxzCkxr6FsHWmy321F9JjF/yCD3BUOR1OGyC3FwTp1/kx5ZfkEa/EjEB7RV
         ThOAewlz47LMeoDPMnJ7jphX68JZ8OAqbKQT0F/yXyKknWEMJqpajQLc8rySq7QF1/lD
         5nnBLJ51TdepwGt/wzT5sweIJmMQEvlJYLsOzPXKS8qLINKIDftuA6xe5lunLtBlU1tD
         5kJ41/WMUl6JwC1pQvqKTUin01CvewPKfrbwm/mO1Dbk8ii1tk3qb1KOJwt/Ft4Ff4yF
         54BOCX86GklhQxLd+k+EqpCQqogd0UFA1RRLDhftGM3IisoM8Jj5TDhYRDgiqRelj8h7
         9c/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nOcRjaFP;
       spf=pass (google.com: domain of mchehab@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=mchehab@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id a11-20020ac84d8b000000b00307ca319443si442008qtw.0.2022.06.28.02.46.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 28 Jun 2022 02:46:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of mchehab@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id D7B1861857;
	Tue, 28 Jun 2022 09:46:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 75818C341ED;
	Tue, 28 Jun 2022 09:46:30 +0000 (UTC)
Received: from mchehab by mail.kernel.org with local (Exim 4.95)
	(envelope-from <mchehab@kernel.org>)
	id 1o67nf-005HEj-Ip;
	Tue, 28 Jun 2022 10:46:27 +0100
From: Mauro Carvalho Chehab <mchehab@kernel.org>
To: Linux Doc Mailing List <linux-doc@vger.kernel.org>
Cc: Mauro Carvalho Chehab <mchehab@kernel.org>,
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	linux-kernel@vger.kernel.org,
	Jonathan Corbet <corbet@lwn.net>,
	=?UTF-8?q?Christian=20K=C3=B6nig?= <christian.koenig@amd.com>,
	"David S. Miller" <davem@davemloft.net>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Alexander Potapenko <glider@google.com>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Grodzovsky <andrey.grodzovsky@amd.com>,
	Borislav Petkov <bp@alien8.de>,
	Chanwoo Choi <cw00.choi@samsung.com>,
	Daniel Vetter <daniel@ffwll.ch>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Airlie <airlied@linux.ie>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Felipe Balbi <balbi@kernel.org>,
	Heikki Krogerus <heikki.krogerus@linux.intel.com>,
	Ingo Molnar <mingo@redhat.com>,
	Jakub Kicinski <kuba@kernel.org>,
	Johannes Berg <johannes@sipsolutions.net>,
	Kyungmin Park <kyungmin.park@samsung.com>,
	Marco Elver <elver@google.com>,
	MyungJoo Ham <myungjoo.ham@samsung.com>,
	Paolo Abeni <pabeni@redhat.com>,
	Sumit Semwal <sumit.semwal@linaro.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	amd-gfx@lists.freedesktop.org,
	dri-devel@lists.freedesktop.org,
	kasan-dev@googlegroups.com,
	linaro-mm-sig@lists.linaro.org,
	linux-cachefs@redhat.com,
	linux-fsdevel@vger.kernel.org,
	linux-media@vger.kernel.org,
	linux-mm@kvack.org,
	linux-pm@vger.kernel.org,
	linux-sgx@vger.kernel.org,
	linux-usb@vger.kernel.org,
	linux-wireless@vger.kernel.org,
	netdev@vger.kernel.org,
	x86@kernel.org
Subject: [PATCH 00/22] Fix kernel-doc warnings at linux-next
Date: Tue, 28 Jun 2022 10:46:04 +0100
Message-Id: <cover.1656409369.git.mchehab@kernel.org>
X-Mailer: git-send-email 2.36.1
MIME-Version: 1.0
X-Original-Sender: mchehab@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=nOcRjaFP;       spf=pass
 (google.com: domain of mchehab@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=mchehab@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Content-Type: text/plain; charset="UTF-8"
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

As we're currently discussing about making kernel-doc issues fatal when
CONFIG_WERROR is enable, let's fix all 60 kernel-doc warnings 
inside linux-next:

	arch/x86/include/uapi/asm/sgx.h:19: warning: Enum value 'SGX_PAGE_MEASURE' not described in enum 'sgx_page_flags'
	arch/x86/include/uapi/asm/sgx.h:97: warning: Function parameter or member 'rdi' not described in 'sgx_enclave_user_handler_t'
	arch/x86/include/uapi/asm/sgx.h:97: warning: Function parameter or member 'rsi' not described in 'sgx_enclave_user_handler_t'
	arch/x86/include/uapi/asm/sgx.h:97: warning: Function parameter or member 'rdx' not described in 'sgx_enclave_user_handler_t'
	arch/x86/include/uapi/asm/sgx.h:97: warning: Function parameter or member 'rsp' not described in 'sgx_enclave_user_handler_t'
	arch/x86/include/uapi/asm/sgx.h:97: warning: Function parameter or member 'r8' not described in 'sgx_enclave_user_handler_t'
	arch/x86/include/uapi/asm/sgx.h:97: warning: Function parameter or member 'r9' not described in 'sgx_enclave_user_handler_t'
	arch/x86/include/uapi/asm/sgx.h:124: warning: Function parameter or member 'reserved' not described in 'sgx_enclave_run'
	drivers/devfreq/devfreq.c:707: warning: Function parameter or member 'val' not described in 'qos_min_notifier_call'
	drivers/devfreq/devfreq.c:707: warning: Function parameter or member 'ptr' not described in 'qos_min_notifier_call'
	drivers/devfreq/devfreq.c:717: warning: Function parameter or member 'val' not described in 'qos_max_notifier_call'
	drivers/devfreq/devfreq.c:717: warning: Function parameter or member 'ptr' not described in 'qos_max_notifier_call'
	drivers/gpu/drm/amd/amdgpu/amdgpu_device.c:5095: warning: expecting prototype for amdgpu_device_gpu_recover_imp(). Prototype was for amdgpu_device_gpu_recover() instead
	drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm.h:544: warning: Function parameter or member 'dmub_outbox_params' not described in 'amdgpu_display_manager'
	drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm.h:544: warning: Function parameter or member 'num_of_edps' not described in 'amdgpu_display_manager'
	drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm.h:544: warning: Function parameter or member 'disable_hpd_irq' not described in 'amdgpu_display_manager'
	drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm.h:544: warning: Function parameter or member 'dmub_aux_transfer_done' not described in 'amdgpu_display_manager'
	drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm.h:544: warning: Function parameter or member 'delayed_hpd_wq' not described in 'amdgpu_display_manager'
	drivers/gpu/drm/amd/include/amd_shared.h:224: warning: Enum value 'PP_GFX_DCS_MASK' not described in enum 'PP_FEATURE_MASK'
	drivers/gpu/drm/scheduler/sched_main.c:999: warning: Function parameter or member 'dev' not described in 'drm_sched_init'
	drivers/usb/dwc3/core.h:1328: warning: Function parameter or member 'async_callbacks' not described in 'dwc3'
	drivers/usb/dwc3/gadget.c:675: warning: Function parameter or member 'mult' not described in 'dwc3_gadget_calc_tx_fifo_size'
	fs/attr.c:36: warning: Function parameter or member 'ia_vfsuid' not described in 'chown_ok'
	fs/attr.c:36: warning: Excess function parameter 'uid' description in 'chown_ok'
	fs/attr.c:63: warning: Function parameter or member 'ia_vfsgid' not described in 'chgrp_ok'
	fs/attr.c:63: warning: Excess function parameter 'gid' description in 'chgrp_ok'
	fs/namei.c:649: warning: Function parameter or member 'mnt' not described in 'path_connected'
	fs/namei.c:649: warning: Function parameter or member 'dentry' not described in 'path_connected'
	fs/namei.c:1089: warning: Function parameter or member 'inode' not described in 'may_follow_link'
	include/drm/gpu_scheduler.h:463: warning: Function parameter or member 'dev' not described in 'drm_gpu_scheduler'
	include/linux/dcache.h:309: warning: expecting prototype for dget, dget_dlock(). Prototype was for dget_dlock() instead
	include/linux/fscache.h:270: warning: Function parameter or member 'cookie' not described in 'fscache_use_cookie'
	include/linux/fscache.h:270: warning: Excess function parameter 'object' description in 'fscache_use_cookie'
	include/linux/fscache.h:287: warning: Function parameter or member 'cookie' not described in 'fscache_unuse_cookie'
	include/linux/fscache.h:287: warning: Excess function parameter 'object' description in 'fscache_unuse_cookie'
	include/linux/genalloc.h:54: warning: Function parameter or member 'start_addr' not described in 'genpool_algo_t'
	include/linux/kfence.h:221: warning: Function parameter or member 'slab' not described in '__kfence_obj_info'
	include/linux/regulator/driver.h:434: warning: Function parameter or member 'n_ramp_values' not described in 'regulator_desc'
	include/linux/textsearch.h:51: warning: Function parameter or member 'list' not described in 'ts_ops'
	include/linux/usb/typec_altmode.h:132: warning: Function parameter or member 'altmode' not described in 'typec_altmode_get_orientation'
	include/net/cfg80211.h:391: warning: Function parameter or member 'bw' not described in 'ieee80211_eht_mcs_nss_supp'
	include/net/cfg80211.h:437: warning: Function parameter or member 'eht_cap' not described in 'ieee80211_sband_iftype_data'
	include/net/cfg80211.h:507: warning: Function parameter or member 's1g' not described in 'ieee80211_sta_s1g_cap'
	include/net/cfg80211.h:1390: warning: Function parameter or member 'counter_offset_beacon' not described in 'cfg80211_color_change_settings'
	include/net/cfg80211.h:1390: warning: Function parameter or member 'counter_offset_presp' not described in 'cfg80211_color_change_settings'
	include/net/cfg80211.h:1430: warning: Enum value 'STATION_PARAM_APPLY_STA_TXPOWER' not described in enum 'station_parameters_apply_mask'
	include/net/cfg80211.h:2195: warning: Function parameter or member 'dot11MeshConnectedToAuthServer' not described in 'mesh_config'
	include/net/cfg80211.h:2341: warning: Function parameter or member 'short_ssid' not described in 'cfg80211_scan_6ghz_params'
	include/net/cfg80211.h:3328: warning: Function parameter or member 'kck_len' not described in 'cfg80211_gtk_rekey_data'
	include/net/cfg80211.h:3698: warning: Function parameter or member 'ftm' not described in 'cfg80211_pmsr_result'
	include/net/cfg80211.h:3828: warning: Function parameter or member 'global_mcast_stypes' not described in 'mgmt_frame_regs'
	include/net/cfg80211.h:4977: warning: Function parameter or member 'ftm' not described in 'cfg80211_pmsr_capabilities'
	include/net/cfg80211.h:5742: warning: Function parameter or member 'u' not described in 'wireless_dev'
	include/net/cfg80211.h:5742: warning: Function parameter or member 'links' not described in 'wireless_dev'
	include/net/cfg80211.h:5742: warning: Function parameter or member 'valid_links' not described in 'wireless_dev'
	include/net/cfg80211.h:6076: warning: Function parameter or member 'is_amsdu' not described in 'ieee80211_data_to_8023_exthdr'
	include/net/cfg80211.h:6949: warning: Function parameter or member 'sig_dbm' not described in 'cfg80211_notify_new_peer_candidate'
	include/net/mac80211.h:6250: warning: Function parameter or member 'vif' not described in 'ieee80211_channel_switch_disconnect'
	mm/memory.c:1729: warning: Function parameter or member 'mt' not described in 'unmap_vmas'
	net/mac80211/sta_info.h:569: warning: Function parameter or member 'cur_max_bandwidth' not described in 'link_sta_info'

Mauro Carvalho Chehab (22):
  net: cfg80211: fix kernel-doc warnings all over the file
  net: mac80211: add a missing comma at kernel-doc markup
  net: mac80211: sta_info: fix a missing kernel-doc struct element
  x86/sgx: fix kernel-doc markups
  fscache: fix kernel-doc documentation
  fs: attr: update vfs uid/gid parameters at kernel-doc
  fs: namei: address some kernel-doc issues
  devfreq: shut up kernel-doc warnings
  drm: amdgpu: amdgpu_dm: fix kernel-doc markups
  drm: amdgpu: amdgpu_device.c: fix a kernel-doc markup
  drm: amd: amd_shared.h: Add missing doc for PP_GFX_DCS_MASK
  drm: gpu_scheduler: fix a kernel-doc warning
  drm: scheduler: add a missing kernel-doc parameter
  kfence: fix a kernel-doc parameter
  mm: document maple tree pointer at unmap_vmas() at memory.c
  genalloc: add a description for start_addr parameter
  textsearch: document list inside struct ts_ops
  regulator: fix a kernel-doc warning
  dcache: fix a kernel-doc warning
  usb: typec_altmode: add a missing "@" at a kernel-doc parameter
  usb: dwc3: document async_callbacks field
  usb: dwc3: gadget: fix a kernel-doc warning

 arch/x86/include/uapi/asm/sgx.h               | 10 +++++--
 drivers/devfreq/devfreq.c                     |  4 +++
 drivers/gpu/drm/amd/amdgpu/amdgpu_device.c    |  2 +-
 .../gpu/drm/amd/display/amdgpu_dm/amdgpu_dm.h |  7 +++++
 drivers/gpu/drm/amd/include/amd_shared.h      |  1 +
 drivers/gpu/drm/scheduler/sched_main.c        |  1 +
 drivers/usb/dwc3/core.h                       |  2 ++
 drivers/usb/dwc3/gadget.c                     |  1 +
 fs/attr.c                                     |  4 +--
 fs/namei.c                                    |  3 ++
 include/drm/gpu_scheduler.h                   |  1 +
 include/linux/dcache.h                        |  2 +-
 include/linux/fscache.h                       |  4 +--
 include/linux/genalloc.h                      |  1 +
 include/linux/kfence.h                        |  1 +
 include/linux/regulator/driver.h              |  1 +
 include/linux/textsearch.h                    |  1 +
 include/linux/usb/typec_altmode.h             |  2 +-
 include/net/cfg80211.h                        | 28 ++++++++++++++-----
 include/net/mac80211.h                        |  2 +-
 mm/memory.c                                   |  2 ++
 net/mac80211/sta_info.h                       |  2 ++
 22 files changed, 65 insertions(+), 17 deletions(-)

-- 
2.36.1


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1656409369.git.mchehab%40kernel.org.
