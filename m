Return-Path: <kasan-dev+bncBDH33INIQEARBDGLQLFAMGQEWTFS3KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id C7D64CC0552
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 01:19:26 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-7c240728e2asf8347170b3a.3
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 16:19:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765844365; cv=pass;
        d=google.com; s=arc-20240605;
        b=A8Qu+VsuDbum8p2R/CBzZPLDMm1Juyf4up5U8iSlPdJhN9xy1hjaj2fM7n7i/7NXLh
         9/4qKZBJY9li/uqui+aWoWALXt0Mc/S+ZmadDV774zNquKQdyeaPa8Stdz9XvZQ8Z/eT
         lZd5rmasWn3GkBo2BNZnWDIjbjnrd/Nls30SWnIELhySLts6T7rRuzmL/+CCUYc7xsFP
         M/RomsgkS4Oy6zKUUW2plyLKOpme+L9hb8j+NHtxAPmCcdZj4y9eShizzb3tfHDdW8Jn
         re2ZGBYkzWFYct4TFdZw+l4iiRi9SWzU7sX8YXaDwQNokzZsvB8wLhiVUY4oMujb9j1V
         ra/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=J0oH4Sdc7luW61uRUfMw4dGorjYDDkBTu1VE7ilqCfM=;
        fh=VW6/Vlk6LiDAtCZpkFZBtE+85gBSJGfRiZLHWhg7XX0=;
        b=geWNeIFugDeiZk95x5WWDN0JJR8KxbWr69aM23dRauUJKwCGKrTuP0TbgFEhtGlJ4t
         7R0lTCaHwo+M7lm/NcEPUGvGECKJ3IsMM823TWFtUfDLcSXAz6lVrfKYy9+TDJKsIb8p
         ERQIbcpWzPriGD5Aw0WIfJ1jmNrDmXUXI4sYeQSsTeLIdP2VLNEDLQvJD0NqFs+9i5qe
         RU5NehgLn2x7MXyHzosYqet/5/L4Xi3fcGPB6gL8o+m6dOdUF5grkq8fSux+JJTBfCF/
         tmKiTXe+YLwHT8ST5mpNu7DRFylyFdUQTdKARx18OHsB5IUV3+pFNhqb5WMFP2YvM1rQ
         G7sw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UlInzzTf;
       spf=pass (google.com: domain of vishal.moola@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=vishal.moola@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765844365; x=1766449165; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=J0oH4Sdc7luW61uRUfMw4dGorjYDDkBTu1VE7ilqCfM=;
        b=i59EvMXAasGT0FeKf7no9ctiSw3PoMyq4Z5TI3ic0kiaR+fd3OEXXPWJDRLHdFfmLb
         7ozucywM8nNv9EsNm9nioqwPlpHYOEeIYIkv1+RMwej5sEg2QtrAKhDeARo59a/N7psg
         VxdRNKQ92PU7mwt12sSDbfJYHg+/3Ln2sktnhFpILczR8gemNCpNI4nIejK2Awpmb14S
         WvngpKnsn0nca0Evy8qU2k/e7i9CFCXKPimCtHKe4Of9c+i+62a2MpN1+y2mHA4xw0+u
         lAibs0EQ3+UydU25gEl6NCniboW8S6G26p6ShUjoOSu+v2xzV5idGvT9BTNHzYC4rhIe
         Ybdg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1765844365; x=1766449165; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=J0oH4Sdc7luW61uRUfMw4dGorjYDDkBTu1VE7ilqCfM=;
        b=XD5fvI3LdogFKHixhJb+6PnzwjsxxEm85RB0HdLYrQQnuMIMpXpB4FecsXD78oZAZM
         RB4rsUamwW9PsbLVxSrD1lLSXuUTLgyI+uqOaVmjQQuY0/gpuOVF6RXbVtuI1DjsBwwq
         n5mbMIg0iSSxqeUa3fifq3nLq3/DDDl7Q0mR4r8nHoDr/CNEtQPA0GRxohy6quz2rAjF
         XHqKW3yhIBIuQh9meBUmbvbDxn4cO1a1xdUAch52UAhtVClvoQzXean+140KC3k5KICe
         ZuqwpeIjxZPv3B5XvVgu7/9hqbNkEVYZg7cSQbe9ljVz4bldeGPQRUy8jVmprGh8oFi9
         IbAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765844365; x=1766449165;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-gg:x-beenthere:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=J0oH4Sdc7luW61uRUfMw4dGorjYDDkBTu1VE7ilqCfM=;
        b=M2fTCaLMNMdhf6PXGPI0eGi6R5lmvYwwH4MHjGNcRZ1JDLtq3h4w4AjqZFpzjUSyHv
         9kYYCnLxXnRcoBKiBLt6BEjv8oZVlM447U8WNtWjNf7D03CAOEQ/pZ99VaTNIR8LMtGK
         ppUEUAqQ2sVz4nQC/AyOJUoouYbtXki0zmr51VDBW0315ZCXH1D5zjZ0rdEkfc+SwVTD
         w7aUYyYV8i4gyJU+GS/Pd1+4Ga47tvv26vKrZIjzGlbEh0YHpsO0gsyeurbflH1dlye5
         qsMKLLhYDSoQWDqVTmjmC4T0TYY/LqLqnZfpTG558ZNarDy2bOm5kTBDnlcoRqqdJmFX
         hP/Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUAibynf8xGzlXD9qrknDWOeGiPt10zR5RdrEerFe74pFm4n7Istl7r5nYCSQ1v6ms2RneIWg==@lfdr.de
X-Gm-Message-State: AOJu0YzazdOVB5r6Hx04dX1+e6QgYfT6ZvMa6HX3H0Rn7B0LFoYowB+B
	J71X7pfgtjACu1RQxkXo1zqQUWYV4ZVka0QDb76a7RpQR+zRNeA4/gEH
X-Google-Smtp-Source: AGHT+IGJGPh0mezwJwUto4GXqvKUQrJzNXJnhB0rPScR1o54RdnFXhgzjzLwgqfyiwfApS0Sy8UUlw==
X-Received: by 2002:a05:6a00:27a2:b0:7e8:4398:b36a with SMTP id d2e1a72fcca58-7f669b8cdfdmr11671275b3a.61.1765844364651;
        Mon, 15 Dec 2025 16:19:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaW7BECk6s3KRbgbM+JDbgPcGt8kSINNXBpt2pdmnlGIw=="
Received: by 2002:a05:6a00:14c2:b0:772:6b0d:37ce with SMTP id
 d2e1a72fcca58-7f647dca0b1ls3961875b3a.1.-pod-prod-02-us; Mon, 15 Dec 2025
 16:19:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWjGyUHUL8dB8TuWFDIOIE3ejHHhThFRVr6UriEukgGuFbU0hze8uIbcV3gFUj1xHZLEzXbfFYy67g=@googlegroups.com
X-Received: by 2002:a05:6a20:3942:b0:350:b8e:f9a9 with SMTP id adf61e73a8af0-369afdf657emr12298810637.42.1765844363171;
        Mon, 15 Dec 2025 16:19:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765844363; cv=none;
        d=google.com; s=arc-20240605;
        b=gPjGio8mzhfaBB4Tcc7iBqAOQK6u923yEBknC6ZxJLz31sitkm5CLjhHBHBNjOPMp+
         i89K0TWDVzYSY1DzerzAYwfcjy7jH23Gtrt9jMryb3ubyX6gBoRIHpZGbsM+u6RPuWd2
         Qfl2Oh/x1xRwtOTVLpdHyQpLO6lWvG+USsKkS3LPtHxd5FwOy4ShQGHO8dOu0+6p+5J0
         yZLKQfnk7AV6I9TofzXfPangcQjAQNxndBE78xXN9OB5Jy9HZxbrvLC1SOoUEXJm8KiD
         ZbJqTZNWS/kgszs5SPAfDMstC4W2bIlE+V14d552+/AI5LnwoDkPq++1z+AVu79Fn0GQ
         8qJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Sk1yhdZDsbmHyAUXRbfG+BCb5AaoOf6d28kSsthudBo=;
        fh=/DeOpR92+ojeY3CM6EE2zqso0FRaOX/6Gg6Llc02Nz0=;
        b=PZRrnGJ7lztzY5Ps7WEEXMQqGwjjPpNYNW7G16QGmuMsGRSK7P2OQChAd77sCIfaDT
         Y+gFZKokiVGpYPFlNMUTPSh9KsnGIDMUoZvwd1PCk7icpGtK9mu383nIO62rJf7Uz0ER
         xIOYZMUXeqjNgFbfVAWrxt14dFLqmilclm511oXEn0xADhSFdwCjp4qxs70mrVrIjPYX
         WsMofhoEhpCkl9tq2SR/MyVnwi06yLwsRu7P93DKWQYsQHX1wtRezwxqvSR8bpL3hENQ
         W7Uk3qtF9uSMLJIGslzhXGQAzGEVH/JsKQCpu/1uRm2zJ/ZlhQlNFYI61WqQmlGqtOHZ
         Q4Pg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UlInzzTf;
       spf=pass (google.com: domain of vishal.moola@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=vishal.moola@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x536.google.com (mail-pg1-x536.google.com. [2607:f8b0:4864:20::536])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-c0c25b7e2aasi389133a12.2.2025.12.15.16.19.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Dec 2025 16:19:23 -0800 (PST)
Received-SPF: pass (google.com: domain of vishal.moola@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) client-ip=2607:f8b0:4864:20::536;
Received: by mail-pg1-x536.google.com with SMTP id 41be03b00d2f7-c0224fd2a92so3792541a12.2
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 16:19:23 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVcGND0RLOltC2/lrBv192HUNe2EJM1AIzFcUpMsOCp6+te/zumZXftiDXlU77IBzRuuQzTO+TNQM0=@googlegroups.com
X-Gm-Gg: AY/fxX4tvyABQRtLp9RhXy0Y0HCxtvUqukF+O3wtWKJJkbP0+1jhblgwlUmpIRDbFzf
	eJmdzEiCI4tfOZqxwRiTqj0GqdqNft3+q1ez4w4n1mgVAhnujCH4dHqkdxVVsPqqefOsaGDe9Tx
	X5AAnsU7T7Z9GkUDrzpTZXI8I8TfV+G/hSsOJILXc5TfSWbBDY0mJV2Ew9bNU2b0Oj2fqE4Qcfh
	8K3w/icQsEWtwJ8lEZof645iZi6fkYNj+9irqmIwt8JlK+NzgOrC0mkaAyj7kzI8tTv3TtFyolK
	nWMq1orudo6rHCJZMV5A7HNFRNjKmm9jQpUfDTYVHjmeB7hHtwg3ep+ncilMf61tZULFnHTE2he
	ORKZ4ZGuvv0tD6KFJUlsdSpCIu7RePBgF9n1pQh2nhx8+WYvDU36n747z1VFGUIV66RP+ycgwL8
	L49+xygzu2JYMYcZAokPAw9gFc0EahohJbdSQxK0S7YNI=
X-Received: by 2002:a05:7301:f84:b0:2a4:3593:6466 with SMTP id 5a478bee46e88-2ac300f729dmr7381219eec.22.1765844362545;
        Mon, 15 Dec 2025 16:19:22 -0800 (PST)
Received: from fedora (c-67-164-59-41.hsd1.ca.comcast.net. [67.164.59.41])
        by smtp.gmail.com with ESMTPSA id a92af1059eb24-11f2e30491dsm51066947c88.16.2025.12.15.16.19.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Dec 2025 16:19:21 -0800 (PST)
Date: Mon, 15 Dec 2025 16:19:16 -0800
From: "Vishal Moola (Oracle)" <vishal.moola@gmail.com>
To: Bagas Sanjaya <bagasdotme@gmail.com>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux AMDGPU <amd-gfx@lists.freedesktop.org>,
	Linux DRI Development <dri-devel@lists.freedesktop.org>,
	Linux Filesystems Development <linux-fsdevel@vger.kernel.org>,
	Linux Media <linux-media@vger.kernel.org>,
	linaro-mm-sig@lists.linaro.org, kasan-dev@googlegroups.com,
	Linux Virtualization <virtualization@lists.linux.dev>,
	Linux Memory Management List <linux-mm@kvack.org>,
	Linux Network Bridge <bridge@lists.linux.dev>,
	Linux Networking <netdev@vger.kernel.org>,
	Harry Wentland <harry.wentland@amd.com>,
	Leo Li <sunpeng.li@amd.com>, Rodrigo Siqueira <siqueira@igalia.com>,
	Alex Deucher <alexander.deucher@amd.com>,
	Christian =?iso-8859-1?Q?K=F6nig?= <christian.koenig@amd.com>,
	David Airlie <airlied@gmail.com>, Simona Vetter <simona@ffwll.ch>,
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
	Maxime Ripard <mripard@kernel.org>,
	Thomas Zimmermann <tzimmermann@suse.de>,
	Matthew Brost <matthew.brost@intel.com>,
	Danilo Krummrich <dakr@kernel.org>,
	Philipp Stanner <phasta@kernel.org>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
	Sumit Semwal <sumit.semwal@linaro.org>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	Eugenio =?iso-8859-1?Q?P=E9rez?= <eperezma@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>,
	Nikolay Aleksandrov <razor@blackwall.org>,
	Ido Schimmel <idosch@nvidia.com>,
	"David S. Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>,
	Jakub Kicinski <kuba@kernel.org>, Paolo Abeni <pabeni@redhat.com>,
	Simon Horman <horms@kernel.org>,
	Taimur Hassan <Syed.Hassan@amd.com>, Wayne Lin <Wayne.Lin@amd.com>,
	Alex Hung <alex.hung@amd.com>,
	Aurabindo Pillai <aurabindo.pillai@amd.com>,
	Dillon Varone <Dillon.Varone@amd.com>,
	George Shen <george.shen@amd.com>, Aric Cyr <aric.cyr@amd.com>,
	Cruise Hung <Cruise.Hung@amd.com>,
	Mario Limonciello <mario.limonciello@amd.com>,
	Sunil Khatri <sunil.khatri@amd.com>,
	Dominik Kaszewski <dominik.kaszewski@amd.com>,
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
	Harry Yoo <harry.yoo@oracle.com>, Mateusz Guzik <mjguzik@gmail.com>,
	NeilBrown <neil@brown.name>, Amir Goldstein <amir73il@gmail.com>,
	Jeff Layton <jlayton@kernel.org>, Ivan Lipski <ivan.lipski@amd.com>,
	Tao Zhou <tao.zhou1@amd.com>, YiPeng Chai <YiPeng.Chai@amd.com>,
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
Subject: Re: [PATCH 04/14] mm: vmalloc: Fix up vrealloc_node_align()
 kernel-doc macro name
Message-ID: <aUClhBdwQb83vN0o@fedora>
References: <20251215113903.46555-1-bagasdotme@gmail.com>
 <20251215113903.46555-5-bagasdotme@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251215113903.46555-5-bagasdotme@gmail.com>
X-Original-Sender: vishal.moola@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=UlInzzTf;       spf=pass
 (google.com: domain of vishal.moola@gmail.com designates 2607:f8b0:4864:20::536
 as permitted sender) smtp.mailfrom=vishal.moola@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Dec 15, 2025 at 06:38:52PM +0700, Bagas Sanjaya wrote:
> Sphinx reports kernel-doc warning:
> 
> WARNING: ./mm/vmalloc.c:4284 expecting prototype for vrealloc_node_align_noprof(). Prototype was for vrealloc_node_align() instead
> 
> Fix the macro name in vrealloc_node_align_noprof() kernel-doc comment.
> 
> Fixes: 4c5d3365882dbb ("mm/vmalloc: allow to set node and align in vrealloc")
> Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
> ---

LGTM.
Reviewed-by: Vishal Moola (Oracle) <vishal.moola@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aUClhBdwQb83vN0o%40fedora.
