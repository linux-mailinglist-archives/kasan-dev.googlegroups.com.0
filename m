Return-Path: <kasan-dev+bncBCJ455VFUALBBYXG77EQMGQE53NIEYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id D36FECBD863
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 12:39:15 +0100 (CET)
Received: by mail-qk1-x739.google.com with SMTP id af79cd13be357-8bb9f029f31sf497238185a.2
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 03:39:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765798754; cv=pass;
        d=google.com; s=arc-20240605;
        b=IXJ2KepvWNlXvztPAya4zyrK/1DIGseg1NE1dCf07MgZ30hApeL14DvSRMuHHbUNe+
         OtMbkUwFtXR22Mb/yO+S6ER2seYuzncNKGSfIZTg5Q1O/ZN+FgJ100xB+CcaVp1v/7qR
         dKviHzYWA2dBaeWyl6d2fdfJ8I44MgFlsa9ClQNWVdxwP7zrAB49s7Lv6VJzHkge+GcT
         5P/sbyFfeVukev8cW7VICEgTy5K1BQ7W5THqbpFCjcu6SUmECkOl48U+BQa+6EAKPoZP
         IiuDZ9cKsPj5xGOirlqYhs5tUHBdPawJ94Ced674XD+b1KxnXr9yH+4yw1GLKUTYqtSz
         I/ZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=TsM6Ft2/+qCP2moyUdFQDD9yoL+9322IFroG9Z5Jv/k=;
        fh=RJd6O+4Uh1CZ7Sc8h4+vTHC8Y17NJe3y6DRa4oNFJ30=;
        b=EMyZ9m8zanJYOO99VVlhzdzOcH0vquOYG4LJtKQaYInPotoTzDwSpWzYO3h99ZY2Xm
         IXIb1EPlQHOE9vKOZjGPsoVFXd3CVazW15duOBLUB4MLNs2g3FwjO9Vg46N2sN0EcpTH
         I/XfhmTop20o50jvSPGjozoygie9vBcySu3GVh7MJsj759s5Bn3Tzm66F1oLYBnZSD2V
         fz4fj2QKE//gjxEH/ULWcOoetWtukgc2vQPqw10WrpfUM/PuNPa9SgZhdF0ZkxD12JPt
         90pXxHSAAUfxY5XvdN/r9o4+jEOFw2kcNhxl9ay90O5pd/T6Szxz63Usk4BKq7370o6N
         jIYg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AdsiZUU9;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765798754; x=1766403554; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TsM6Ft2/+qCP2moyUdFQDD9yoL+9322IFroG9Z5Jv/k=;
        b=fAdz+5Ta4MpLQiXV5PzYhnVd+HDiWw8v4XC1wGDgVOpuOB0yyEQVc1vDpcXg0X2ol1
         AieOeAsoQBzaOhEiPM5+PagB/pshwPssOlfORPzXC4v/1Sxjy+7iNZehOBzOeTJ8TdYY
         yPiiLITTq25bDTqHUkb0ZhAUhZeFyBevNk4WbrapUYUWA+hGUvOuUa2OMHb7olGVn7kN
         GLMqEVnFt8N9DLIghc+bmcczV4rWtCWADQo+WByP6lVBJwZ8pJR9QQaZ2eEVGAxyztpf
         kPmb9Lo+jFE4MEYulNWghmzzN5BMfHWCzKahx2D4iP6myl6Q7ysI60ikxN11dcnQkOuJ
         a/2A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1765798754; x=1766403554; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=TsM6Ft2/+qCP2moyUdFQDD9yoL+9322IFroG9Z5Jv/k=;
        b=dwVrmsrwGpxWPgC0NG662XKOuWM+tymOWukzTXW7HBwKlzAzcCJFzteCuzJfE7Y7W5
         Q/WDXqjCiSxstQgDUxURjp19fL2ohhftSiaHpcFXM9ITUunbnMVfQJk4SUOR4IKIGJyK
         ThpbqdAAcDMYzOxjCqnW/c2bNn59ZeZELcvZs31uD9UdEXxQW7W4wHlHvDQlB1mgPlvI
         OnMezW009SFwUtzGxvlpngGXBv/ZmFR4pOlMX/SvndaYkP5PySa8siCdaGhLYe52kalx
         WrqMY22M6dC42LxM7QldDG19Kw2zVJNdWTPePvvis57xWiBeiOwmL5uuHzm377mtuH5R
         AKyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765798754; x=1766403554;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TsM6Ft2/+qCP2moyUdFQDD9yoL+9322IFroG9Z5Jv/k=;
        b=WqNo66VRKo8xpMYlSPaQJJezUAsSLpgdFc/4PVza88dM9OggR0jyVTI3IzfEjsKihH
         TV48rYohOJIfq05+5K+sKcIYaFtath0RlFbr9Wy++3d9sTMmdbCp+QsMN59j5/dFL2o7
         iKKi5cdOydrwwESJI7TIKfAYH+/GfgkK09JIvP6mW8LW78rPVzctxwZjrf+G/mIvSHJE
         DQ9VQdfaX8hdoGvM0UZtkzicBGOAChFCzjUdBMUiz25c8S+BQzKocyDGOZluFYE1Oup2
         wlKMIIG7kaaIx4LnaokGpHS3K3DWmETxroWecoCrXs74SeRyfo9cc7r6H5mwxkl/hNGF
         cePQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVyzz5F3FhUXG1wvbh2V0lPTdWRoUUVva1lmwHmPJLsd6BzYfKaySPmnDr9f1apfr9+x5ywOw==@lfdr.de
X-Gm-Message-State: AOJu0YxzrmhuNlNhhiIbH18aERi3x9jazrhLIAx7/WE5X65D569vcwXS
	T7hqcTiQfJBNCykoKG+Ga0hRTjqERGkuUnYLmltxh5tYhMp7ZDEXqeaj
X-Google-Smtp-Source: AGHT+IGQzf455BOuBmTN0A9ByidgGCnrbm2cm8ohIWG2XC+KORPKBdAkO+MZR8o0X9aDzkzHLbjntg==
X-Received: by 2002:a05:6214:398a:b0:87d:f30e:550 with SMTP id 6a1803df08f44-8887e7a08a9mr166183776d6.37.1765798754314;
        Mon, 15 Dec 2025 03:39:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaUzK13kilZFUHoald0YyV57YCbUAeywK8A+9LdgcKQ1w=="
Received: by 2002:ad4:5d6e:0:b0:880:59ee:bbc with SMTP id 6a1803df08f44-8887cd340adls4814656d6.1.-pod-prod-09-us;
 Mon, 15 Dec 2025 03:39:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV0JiPul+sQFtjstiQolGMZwaXp9wFbcfXDchqYGUUMvV0MHeGV04TrzTIogfFP7GwmSPEmaVTGBdI=@googlegroups.com
X-Received: by 2002:a05:6122:2213:b0:559:85d5:bfbe with SMTP id 71dfb90a1353d-55fed63810dmr3092587e0c.15.1765798753531;
        Mon, 15 Dec 2025 03:39:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765798753; cv=none;
        d=google.com; s=arc-20240605;
        b=Q3ZzFqnUMUnyi6rkGlnDqXo/KBX4EhkwmIluHcdSNIynXaxeZ8HDVB8frW23qqmDuX
         fjVljZte4UPHu9qQamtdlcFa78SFS95X/gZgixrj6iUa3VhvFKKJ4HgMcQss9+wLjogI
         krPDdSkGVWTHFJ1zvbrJjT+hTISxF7pz3r7fHmZ2qAeiVSq5VnWCtUeQYzVcIEjhadYp
         5femQVQywbqH0nQDKGkdFAb+fl2KEQgicV8pzHsC/smT/IyXI7WdHAqk3HrQtzBKe+3+
         pDJh7fNzZSWSlQlrcmPz6ljEqG1ZC24KAHTY1zltI4Y/ZeJLYLYUY2LX3dhdebm+AZnI
         a6pQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TWXueLrhDneeDmCGizpSHzMSgAg8yMgxTmeT/qXEn+I=;
        fh=+VlDvXEGfNjCjCDRoO9gnB30s3FkvUhkZhHHMqfj/Ck=;
        b=Fb+WYQ659i+QYr2W4uJPQYPT0eF3emGLgmr6s1g8vBiuTW7nl2Xb/dYXZ+uIYgRgWW
         bB70qK6jrZR4aoABWEYEqeTqv78y8Xfb6Zuc8yITQlWljesCj0NzB3ZT/sF1QiMuJTNW
         ITIcYPq1KFqdrugaeoEGUUwklGdwY27ZVqrOZqyaS85RsHPgyX9JM/FxgJihOtW4qBK5
         KZ/gg3jGXkwHeriYJyzdXBqxSCsjgiyaf2HaXl//2vk2Uky6g85DlR86rPG/hcfw5pip
         p9+4038ZKyj97cWgCXzXI2i4a+4F/i/ULTYYYxjbrXbkOL63NSTBLSfI6TIOTFSGn/g9
         YCjQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AdsiZUU9;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-55fdc47fc84si482407e0c.0.2025.12.15.03.39.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Dec 2025 03:39:13 -0800 (PST)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id d2e1a72fcca58-7aa2170adf9so2622319b3a.0
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 03:39:13 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV4X4iuX7qAM3+kqMmUa+IOcaF7LxOgcC2sCC8WVXEedVbfclJnQ+GmnBOp2qrhmoCKzO0vMnKbMVo=@googlegroups.com
X-Gm-Gg: AY/fxX7SxpoR8FHTqTsxFF5i5z0BocTl4W3/RkdG2ytZz2JFArL1rqOvFrxKcI9L56Q
	OebS4fava8QncGYOrVd/UjArd3HV8al5YUKYDSNSm4a8XQcJCmsNmBI1kjCYIflDhQ+SMIhkKuI
	49T7UR6/rSnjgAdkfdsOo9oyI9is+3YJgtHGzbREdNqxVQq6Spf1NCWSP+mSyVH1Oz9MoK8/zkW
	vQJ5sRr5fBsRTaH+0/1ewVkF/q98ylorjwa2aMiC/mF5VajvoA5HBqbFhpejbICvXLGMpB8e8Xr
	sxNsDXcMwNfp0NlTkrFZxLL2cS/leYKAWGjXQLf7+ORzZza+GwiZT1pcw6hHGXud5ERH5Ot6zHB
	sHLJz4gzos2VBZu/JUmm48Eq9IJvCF8fV25VhKdtV35ws64ZxvgMH3PGmzjLxIAtLOMDrUW61ii
	XKNIwPVEK07dk=
X-Received: by 2002:a05:6a00:ad08:b0:7e2:bf6f:f782 with SMTP id d2e1a72fcca58-7f667a2ba3emr8430635b3a.28.1765798752974;
        Mon, 15 Dec 2025 03:39:12 -0800 (PST)
Received: from archie.me ([210.87.74.117])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7f4c27769edsm12505512b3a.23.2025.12.15.03.39.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Dec 2025 03:39:12 -0800 (PST)
Received: by archie.me (Postfix, from userid 1000)
	id 504F3444B392; Mon, 15 Dec 2025 18:39:05 +0700 (WIB)
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
	George Anthony Vernon <contact@gvernon.com>,
	Thomas Graf <tgraf@suug.ch>
Subject: [PATCH 03/14] textsearch: Describe @list member in ts_ops search
Date: Mon, 15 Dec 2025 18:38:51 +0700
Message-ID: <20251215113903.46555-4-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.52.0
In-Reply-To: <20251215113903.46555-1-bagasdotme@gmail.com>
References: <20251215113903.46555-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=896; i=bagasdotme@gmail.com; h=from:subject; bh=1tOY86lhWOCbSHsqmK/tuDEilXGPwKXl/15tM3wSixs=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDJn2n4Mqzx7cbGl2s1Xb5iYDm7bLkws+2881173X3pa/f UbeT2+PjlIWBjEuBlkxRZZJiXxNp3cZiVxoX+sIM4eVCWQIAxenAEzk0hqGfzoRZw50iXbWS+pV RRyxzVGfNT/eQV3w9+MclUw9PumMlYwMO5cdc7i131P/rrG85octa1tun66WP3rW6W/Ropnr7E6 G8AIA
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=AdsiZUU9;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42e
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

WARNING: ./include/linux/textsearch.h:49 struct member 'list' not described in 'ts_ops'

Describe @list member to fix it.

Cc: Thomas Graf <tgraf@suug.ch>
Cc: "David S. Miller" <davem@davemloft.net>
Fixes: 2de4ff7bd658c9 ("[LIB]: Textsearch infrastructure.")
Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 include/linux/textsearch.h | 1 +
 1 file changed, 1 insertion(+)

diff --git a/include/linux/textsearch.h b/include/linux/textsearch.h
index 6673e4d4ac2e1b..4933777404d618 100644
--- a/include/linux/textsearch.h
+++ b/include/linux/textsearch.h
@@ -35,6 +35,7 @@ struct ts_state
  * @get_pattern: return head of pattern
  * @get_pattern_len: return length of pattern
  * @owner: module reference to algorithm
+ * @list: list to search
  */
 struct ts_ops
 {
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251215113903.46555-4-bagasdotme%40gmail.com.
