Return-Path: <kasan-dev+bncBCJ455VFUALBBXXG77EQMGQEJFWC2KY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 92C0BCBD85B
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 12:39:13 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-34c93f0849dsf1015641a91.1
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 03:39:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765798751; cv=pass;
        d=google.com; s=arc-20240605;
        b=Nd+hH2S+7Co/K4Ka78pQlgLF6Z79qEBD3GxMF+7MxtqgCCrdpFRzGieDF9WjpW0S0J
         L2vlJ1pGKDpSLYPy1OE5ET8K12C2Sdj2TBp2ly6mTXDbS8Fmlzs5EVW28b/NiuBzCN27
         88EPgXFYVBm11aGQKqnNsN2vqddqvskl8gnI+hP/eHqTdEzyC8pOZvKBFwAU9iiNfj8H
         xKcrVyXdg4WsZUihbQs8UhyQtOYIZUacPXjUHxg1Em5vz0TLKWhNmw5Uepbpnbwg6UhI
         1N/Fgj601e811WKFItvDP3R6AINAIZ6bgZc2TNENSrVzNFP9KLcJsMImnbOxpXnWOrqA
         HnYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=Y2l12z6Ajv2XNT6QvTa6zfsB4DXTmeQ6gpFnt+y2r5Y=;
        fh=D7RROdaPihoO57eYMJmg7c/GjCAjtUHyKdIFFBfPsHU=;
        b=A1vNYDoSHjnKivRJRkAC6DvDsuSYyXJwB8dpPyJTTTDqN1fpjRHc+gRQ+Au2CujC0z
         UJZRN3twb4LueWRkJHgyKohySuf/OJebPu5YkzHgrjkIDFYLFMgl4O6/l2GYTRqkhwLj
         n0Cp7V2Q8AROp7HYYcUbBqQ5C6sqlcVjLWofvqpc8KQPFKMIZYvEFXHPrL3C51tnG7s4
         tLqQFsvdRJvKrbjuxh3/sUpTuqYhIA5ERWiZ1sBCIOfzkAcmY3XPLH3EY3XD2AkN7mqy
         0W0QeW4TnNsgRaKO7uBRC0PgYYxgYiZBne/Hr+yPMhFjgvByy45Nokh7j3VA4SZnYRkv
         cKyA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Ely/j6ab";
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765798751; x=1766403551; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Y2l12z6Ajv2XNT6QvTa6zfsB4DXTmeQ6gpFnt+y2r5Y=;
        b=HffCisEX5JaXuE3VwSL9MTa5uCqRjrcl/dzhGq4NPc0PbNwC17QaC5UDVQqpuLOMLu
         3E2x3PaUltFiH4DuWP7SX7ZhRCfTGhTl4WxrecitlPiHFmgWiqrzyYtpXkbHWm1tTQ7x
         DeELyPaO8MhAB2HtEn7ptvpf9+9UmKJBqFicoIRt74KijaJOABXH7ixjVDqRYiXEswlJ
         6t3BQePZpp/XdFErawWhfPkKpO/b5Y/CvIP1Z1Yt+uJFdBkfL7AMpGaZOIASKzh/jjZC
         WAPYKeqruE51GPcFr754gnhbG4uwl9FoR1E/1bmMC2f9ra2rGg2PO4WcwKVhdCLKvyDH
         VM5g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1765798751; x=1766403551; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=Y2l12z6Ajv2XNT6QvTa6zfsB4DXTmeQ6gpFnt+y2r5Y=;
        b=AEQluMC127RniXAHuppX++Rm55HrRka2xt4cMIET706l4260Y/zNQOKC3xBJuc+SGT
         Wvdp4qGq+HPXGFKx6v6pSjlfJCORx6UcYkfzSE1n/P0w7SIjx+IPFeYofy+5U39x/yfe
         UcBtRHbAc0Sw85FZhr3nnw6TQ4aY9HlbZpY5fuRGljzpYT6L6cL8ZKeBnkHo4tonfbRS
         gS8PysYhCwtwkzznwXDDOvOXqHRDe5V4SVvVNU+AeCo/YXOzl1ibGCwWaHpTH78RbNmu
         c9c4GVMQj7GH3vTHlQl4JfXhI6oOrtqr/U3jY0c3GSL8ewL++I31Atn5Pi6iuipNpp6x
         xJPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765798751; x=1766403551;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Y2l12z6Ajv2XNT6QvTa6zfsB4DXTmeQ6gpFnt+y2r5Y=;
        b=QWhJCQcJpYxrfaMnUIEcDL0fYWIocuaM78mtWGprpYOSLZTZfXv8h8EzUGV+OrBj7V
         zZn1RHuxaJVb8VXh7sx9/IyAQtG34TGubpZWiBBNWczxkM8/iwsvnTuEY6FpKs+/M+g7
         +pkNucHv37o5Chvwufx+/y41aIyoFcXi+Wgbt4FFs8TkhcG1wLi1YIoyOemIxWbGEl5h
         I0LXAUxW+ieP3uMzgIDXoXP3qss3sBYK7OHFH1kUd2zOSjYIk+Kgy04KVSzRP5RxDMW2
         eLRqayoB42uX3UlcipnlFCh68IMDqrf6QP10O3jFIWQ9m7PKsNiAKkez71nv/kAV0BOT
         d/MQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXEpUkAHxepUn/NdjyRWHh0aOS62z3sk1U8w9Yl1IIUeLutXENPhDgQ/lVBhpfo+HHj3sTrmA==@lfdr.de
X-Gm-Message-State: AOJu0Yzj+tIaxnPPMUbB//Or//iDzHP8qFlpUYw29b2HQHv7sjoDxmd5
	1yJs4heNNyZetwnYbtCVPkXJ9ti08+9WXkY4KaVdI/dWmK1ow3v7qYc0
X-Google-Smtp-Source: AGHT+IEtmp1y+mSWBgwd8LgT8SGg6kQ7PX9kIl39iHLFiX8klSIR3oGPbEBDeTRI1Y2LGBuoIC/DkA==
X-Received: by 2002:a17:90b:180d:b0:340:6b6f:4bbf with SMTP id 98e67ed59e1d1-34a926ebf02mr15362569a91.18.1765798751402;
        Mon, 15 Dec 2025 03:39:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZQelEQrXAZhDYr4BLTrzfeQq5Xny7tnbgQoPCEQWnulA=="
Received: by 2002:a17:90b:1247:b0:34a:4aa1:8b1f with SMTP id
 98e67ed59e1d1-34abce8ceadls1359302a91.1.-pod-prod-00-us; Mon, 15 Dec 2025
 03:39:09 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXUNM+/6eW7MT0iiAduKYfZ9cIB2tvJe6sKzgRuItQk8zS7hTjBdjkjB/kM2HiCZZSwv8DAZmhPmok=@googlegroups.com
X-Received: by 2002:a17:90b:4c90:b0:32e:23c9:6f41 with SMTP id 98e67ed59e1d1-34abdc6855emr10106071a91.5.1765798749448;
        Mon, 15 Dec 2025 03:39:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765798749; cv=none;
        d=google.com; s=arc-20240605;
        b=AjS8g8DIU1kaQmHr7dJ9U38FyeqrPNKMoM/7YyGuoiknm0Q1pW62mBVN2JVZn7yU12
         Aya89JAZ7kH2IHuIigJ+x3E8mzA3aeBRJGnNKG7vpDDenkGC4DVRKLxn9cyUzDRLunEe
         OdceenB1Xg9Ini8t5WAOEdw8XFSZqTf/AWFa9X157l7ROpNZB/p44304Gl0qaXFbi/w3
         m/NMNr7teS0MovanBmoqpziOHmxFs6Ff8kQwQVBv84w4qgYnEO+i9orSrnBrT4O3RXI5
         OL55WsMna9MEYyvaSh9e8L+kO2gQTq4s8JnN/AGvpQ77S3UVS8uzNBiqWPYIOsmrdjE3
         mxNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=SOExJIUd6SMMpu9ecZcijfoRnX+3TKAUcxRzAMDO5OU=;
        fh=RZrpv8bEH9CJGAvPnoGr0Nf/GFiaLFQ1aMlCW/sXojI=;
        b=LplArwHQnG2gCb23NU6FLLWYA25YP3AL+UdQdcsy+rOLs1w2jc04on159ALAe7NqHJ
         c4qmv/iqi2RTPsWlkJ45nA3mmcLPxzBU0EE6N8llygLVHDa6rDAye/0NsEN+Nh3vyRxr
         JmNHx9WgammX+H9q72d+XR3yZsF2pjlsNhZYMrsZMP6tCgHdWMtF4zOnjcQpScxcFamC
         wDMTis5HX472T7Ly5TVIQ/ohDXEUJgfDwXzJ3cPljKNinxmPvNztrJjShbozf6m8/cFn
         6sY9SyijSvX5ynouZzMqrGuLhvu4lLvUyV2hrtDMWo8R5gUcLnURRw8YRJdnAVJGXqso
         YglQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Ely/j6ab";
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-34abe274af2si161553a91.2.2025.12.15.03.39.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Dec 2025 03:39:09 -0800 (PST)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id d2e1a72fcca58-7f216280242so956371b3a.1
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 03:39:09 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWdV/UmOYyAjUYTguwi7Bu87Zr/3h6MYZ4ReXOX+JpNZ2seLf4uFdnO9tMq+bgcD29qauITfKZMN7o=@googlegroups.com
X-Gm-Gg: AY/fxX4wGqCVkQGHn6qDkp5W6SbGmiMET+itbSzncxkdhBJnmkX4d62HoMxlqzoCMub
	zP5g4AnLIoJQ4ZfvWayKXSEeRCinVHWTDHI3D28gGo39oS5RZ79PdD7/jQD2qBAhRa/xlDz34M4
	ZEkq2XosBcpqnSSfChPnA38YlgXOKtqFSmrDKMVOASyoTNXnYt5GWcX5fPVDH1T9Mt8z4srWwIG
	7JMc8kGT+UVUa7OomqvgXKJLl2c+o7721KHmzwSNkaap3PcTocFPO41QlPkTzIRTI/28GzIvf1D
	VxfKB3tLPN23SUjJntQ0U9OOhv1SfX7xGjLKh+uf+uHJuAa11sL72phmDVoZ5DXENKUvIcgNzRl
	bfYdyzXvYGyWzoKrfXWPuE/WTvxNQdquavaTbRoy0CSl4TVn9gf1cPhrIVSzc/yoZ4MO87eREhx
	crlTbLZGsFzj0=
X-Received: by 2002:a05:6a20:1582:b0:366:14b0:4b18 with SMTP id adf61e73a8af0-369aab22577mr11102662637.35.1765798748789;
        Mon, 15 Dec 2025 03:39:08 -0800 (PST)
Received: from archie.me ([210.87.74.117])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-2a05689dcf9sm83488865ad.98.2025.12.15.03.39.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Dec 2025 03:39:08 -0800 (PST)
Received: by archie.me (Postfix, from userid 1000)
	id EAE05444B390; Mon, 15 Dec 2025 18:39:05 +0700 (WIB)
From: Bagas Sanjaya <bagasdotme@gmail.com>
To: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux AMDGPU <amd-gfx@lists.freedesktop.org>,
	Linux DRI Development <dri-devel@lists.freedesktop.org>,
	Linux Filesystems Development <linux-fsdevel@vger.kernel.org>,
	Linux Media <linux-media@vger.kernel.org>,
	linaro-mm-sig@lists.linaro.org,
	kasan-dev@googlegroups.com,
	Linux Virtualization <virtualization@lists.linux.dev>,
	Linux Memory Management List <linux-mm@kvack.org>,
	Linux Network Bridge <bridge@lists.linux.dev>,
	Linux Networking <netdev@vger.kernel.org>
Cc: Harry Wentland <harry.wentland@amd.com>,
	Leo Li <sunpeng.li@amd.com>,
	Rodrigo Siqueira <siqueira@igalia.com>,
	Alex Deucher <alexander.deucher@amd.com>,
	=?UTF-8?q?Christian=20K=C3=B6nig?= <christian.koenig@amd.com>,
	David Airlie <airlied@gmail.com>,
	Simona Vetter <simona@ffwll.ch>,
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
	Maxime Ripard <mripard@kernel.org>,
	Thomas Zimmermann <tzimmermann@suse.de>,
	Matthew Brost <matthew.brost@intel.com>,
	Danilo Krummrich <dakr@kernel.org>,
	Philipp Stanner <phasta@kernel.org>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Christian Brauner <brauner@kernel.org>,
	Jan Kara <jack@suse.cz>,
	Sumit Semwal <sumit.semwal@linaro.org>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	=?UTF-8?q?Eugenio=20P=C3=A9rez?= <eperezma@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>,
	Nikolay Aleksandrov <razor@blackwall.org>,
	Ido Schimmel <idosch@nvidia.com>,
	"David S. Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>,
	Jakub Kicinski <kuba@kernel.org>,
	Paolo Abeni <pabeni@redhat.com>,
	Simon Horman <horms@kernel.org>,
	Taimur Hassan <Syed.Hassan@amd.com>,
	Wayne Lin <Wayne.Lin@amd.com>,
	Alex Hung <alex.hung@amd.com>,
	Aurabindo Pillai <aurabindo.pillai@amd.com>,
	Dillon Varone <Dillon.Varone@amd.com>,
	George Shen <george.shen@amd.com>,
	Aric Cyr <aric.cyr@amd.com>,
	Cruise Hung <Cruise.Hung@amd.com>,
	Mario Limonciello <mario.limonciello@amd.com>,
	Sunil Khatri <sunil.khatri@amd.com>,
	Dominik Kaszewski <dominik.kaszewski@amd.com>,
	Bagas Sanjaya <bagasdotme@gmail.com>,
	David Hildenbrand <david@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Max Kellermann <max.kellermann@ionos.com>,
	"Nysal Jan K.A." <nysal@linux.ibm.com>,
	Ryan Roberts <ryan.roberts@arm.com>,
	Alexey Skidanov <alexey.skidanov@intel.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Kent Overstreet <kent.overstreet@linux.dev>,
	Vitaly Wool <vitaly.wool@konsulko.se>,
	Harry Yoo <harry.yoo@oracle.com>,
	Mateusz Guzik <mjguzik@gmail.com>,
	NeilBrown <neil@brown.name>,
	Amir Goldstein <amir73il@gmail.com>,
	Jeff Layton <jlayton@kernel.org>,
	Ivan Lipski <ivan.lipski@amd.com>,
	Tao Zhou <tao.zhou1@amd.com>,
	YiPeng Chai <YiPeng.Chai@amd.com>,
	Hawking Zhang <Hawking.Zhang@amd.com>,
	Lyude Paul <lyude@redhat.com>,
	Daniel Almeida <daniel.almeida@collabora.com>,
	Luben Tuikov <luben.tuikov@amd.com>,
	Matthew Auld <matthew.auld@intel.com>,
	Roopa Prabhu <roopa@cumulusnetworks.com>,
	Mao Zhu <zhumao001@208suo.com>,
	Shaomin Deng <dengshaomin@cdjrlc.com>,
	Charles Han <hanchunchao@inspur.com>,
	Jilin Yuan <yuanjilin@cdjrlc.com>,
	Swaraj Gaikwad <swarajgaikwad1925@gmail.com>,
	George Anthony Vernon <contact@gvernon.com>
Subject: [PATCH 01/14] genalloc: Describe @start_addr parameter in genpool_algo_t
Date: Mon, 15 Dec 2025 18:38:49 +0700
Message-ID: <20251215113903.46555-2-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.52.0
In-Reply-To: <20251215113903.46555-1-bagasdotme@gmail.com>
References: <20251215113903.46555-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=962; i=bagasdotme@gmail.com; h=from:subject; bh=yvRLY8BHqBHKchvPjcPm3zDNVddYxArgXi7Qv6PDXBI=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDJn2n4MeLjlRVOvo/zL51uM7fT8nbubcy37qLGeos8/kb VKe75YIdJSyMIhxMciKKbJMSuRrOr3LSORC+1pHmDmsTCBDGLg4BWAiGosZ/mm4fru/UqLr5XIZ H96Qry1BDLd3LedR2Gkharj+Q1jej2pGhm7zlf21hfvmpVcxGBvN2yCmrfs71+wCw2eFqbVucQl NvAA=
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="Ely/j6ab";       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::431
 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Sphinx reports kernel-doc warning:

WARNING: ./include/linux/genalloc.h:52 function parameter 'start_addr' not described in 'genpool_algo_t'

Describe @start_addr to fix it.

Fixes: 52fbf1134d4792 ("lib/genalloc.c: fix allocation of aligned buffer from non-aligned chunk")
Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 include/linux/genalloc.h | 1 +
 1 file changed, 1 insertion(+)

diff --git a/include/linux/genalloc.h b/include/linux/genalloc.h
index 0bd581003cd5df..0ee23ddd0acd3a 100644
--- a/include/linux/genalloc.h
+++ b/include/linux/genalloc.h
@@ -44,6 +44,7 @@ struct gen_pool;
  * @nr: The number of zeroed bits we're looking for
  * @data: optional additional data used by the callback
  * @pool: the pool being allocated from
+ * @start_addr: chunk start address
  */
 typedef unsigned long (*genpool_algo_t)(unsigned long *map,
 			unsigned long size,
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251215113903.46555-2-bagasdotme%40gmail.com.
