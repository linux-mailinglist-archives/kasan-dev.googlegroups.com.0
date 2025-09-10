Return-Path: <kasan-dev+bncBCJ455VFUALBBTGPQPDAMGQENIAFENY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 91822B50BD1
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 04:51:58 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-31d6d431b64sf2891730fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 19:51:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757472717; cv=pass;
        d=google.com; s=arc-20240605;
        b=G1MVE3pKhzVpwSJOzn1QJ6E6J19+aw+XBJAMxTPxr2F6Czys1ejd8XZtEIHVkVmEYG
         Q57OSsDoedPa1fs5HGXevBJWb8842uxloon3w9JRY8ZKt6nLj3xL+kpTCuoX8ZLsb7v4
         cRFYJKOh3zfMHbSc4fMaEqpduvYIxkxJMnzQ6QQlD3jQwh4kQWafSEw0wVdr1srE3/AD
         TCNzzFpjeGTcwo1CbQX6ucB+NK3IB3w0AD0eVwqQy41OHrRI0mENTlE+/4xC3736+2TJ
         xVD2FdxDJWoYcGV4HuaA6xCjZCSfC7vpRfRmujX5sNjfM/sweSJfeZg/6mwT9/Erw6yi
         dkzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=Lrzq1wufW26T7808BU3KvUgy1h6thLuU+n8KdmIB+xE=;
        fh=qsPD2kHj4mbhO21SurGFxcehm8mWN65aQda+XZdnSqU=;
        b=e1QfQF26eXdzRzbp3y8Wr4pFeiyBgnmjKJ499R6J8BXPPGsQ0evvJt1hAUbNSTsUQb
         qnwed8Z6L08FDoek4xdXQjflQxUBqPBG+Ij4rDXGg5FkvaLOoMB8cHOOeQkyMLiMig3U
         keqcGh8dPdE69lT2qr4YDccAmLavrWlAl5GfNWQcuDiu8X16EVqnAXA0Ncv4Lgwklbxr
         m+pph49M3u2s86sqAAXAyscZ9UwBaDccSHaJCsfBOpOarZp6btq8MrUCNm92hEzpXP5d
         Wol3NmRjsPJMl9MguWr7DL3bpoEPyPmr0n2dD6MWWdGC1MiknYPZwZxWRDPDGln2FM2r
         qAOA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FtyBRJUc;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757472717; x=1758077517; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Lrzq1wufW26T7808BU3KvUgy1h6thLuU+n8KdmIB+xE=;
        b=lILJkrG4WGnxyXl2lWDEef0KRNaDzJ/gz/xS35Z4ivEtm+7p9sE8+ZErU8GIcLQnke
         lzEhagdpNCrBONfk7/DEzm11MKdFkHykr2Byrl0WmbDEYm30QBhv/2MQO/9+/XCsJYux
         RNu2Ecdgb20tixulMhWnvYgoM1BM213PelbriSmiAI6tgZkFkXe2mzkw35jpHbtNFJzI
         SpW9k2xozlf6a03TKXhwzbA42JnhhPMn8HxHchnQdkuHEuUCLD705q5mas3+SkAm/C9j
         14r0ZprP2ATDkjbypIv6hcqzh/YKpcPN2fwqW/eb62HAwKX1AbAy3KKawvtHnr37W1wF
         TMrw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757472717; x=1758077517; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=Lrzq1wufW26T7808BU3KvUgy1h6thLuU+n8KdmIB+xE=;
        b=QSvp6kgATZC7trYSUM+Wp4eCLzTJse9XEH9QKOJ7Pd+e5iNRBz6x1i/RUo5FCI7uAX
         V0YXHvdnyfRBrMTKRzK38uqb++NqHKQNPu0/T60BF4HVJ8LQvdkgQLJVrkqvlbfbh/0V
         RcU75g6OxUbhHuwX17LIPTkqQjAoPF5knGiHCAXAwzE+oDaCJ29yItEjsYDpZlZctAwc
         zfarSxwuyQXCDVsWnbaWWaNdT+Fv6xLUStj2/jnQSJJppTixT1E9VZoeRVoYXsZQ/j16
         uMQ5Va9OFKbSlIsnzxDApj1Lsc3s/JAivXAd8QeRvjsF+RCFlUH3gnHVcZnRhD/FdjY+
         s9IA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757472717; x=1758077517;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Lrzq1wufW26T7808BU3KvUgy1h6thLuU+n8KdmIB+xE=;
        b=Kq+ImAYwxuzACW5lM6GsMKTM44vCQMx3cc+rg2O6K20lVwR1qQK4gALBwlBHJVRWKp
         MwIEgnyqbwSYPCiw6f0gNGU+dwjXVFo8/mf7lUxlw4rK2xayij81h+Dn4GVILXSCsW/9
         ID6MlCWZtrS9T5qJiTQGbpGKViUSHBPzBSHDQUZLdCiEEZOkNu5Ud4EYJPiJ+QzTwCI2
         uaNV5Z3ZnpQke7xwgYytKyufXGaq57JWrd25S3w2/U0czi5hEd+gpnulWh56ZQj84p4w
         JJ2YQ1wqFJMYI2+fzxr2yA2hmqsSqErVsG7fhDa7QSLFBMq5mWjUHq7iYfGS99s7wAHT
         loaw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWhrmpRjyqXsGO4AV4LnsdOpOg7JkHVXyNqhxqR51cVMQms5b7FtX/LS5IddjWcDj9ivfiZtQ==@lfdr.de
X-Gm-Message-State: AOJu0YzHvyhdGJh0PK4wYgyMOyit9UEPHMtFlKZyXAd9y+XJqvm7/rd1
	5KIv2PHJr1IpN1O1ohN3uovNNcPdVItiQchxf52aMPP6OjhFPvZY0Pa/
X-Google-Smtp-Source: AGHT+IGMyWkadQ+U50sF5yW+KLrMC05WWbueCPp/vdn7aNCpZcVNIAYjXd2R3lVyAen4BmYXfeOg7Q==
X-Received: by 2002:a05:6808:159b:b0:438:407e:4b0 with SMTP id 5614622812f47-43b29bc7062mr4914430b6e.4.1757472717139;
        Tue, 09 Sep 2025 19:51:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4RwwzXO04JF8ATS3fPOBjXHs60LR1mt/JLAXJp7cjNag==
Received: by 2002:a05:6870:e0a7:b0:2ef:3020:be7e with SMTP id
 586e51a60fabf-321270fd0a0ls2927879fac.1.-pod-prod-06-us; Tue, 09 Sep 2025
 19:51:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXtgK5NasUMxsn99/Mt4xkHBNaQvvnZ/wuSZC4FcPO2On6B88+4Kb9f7/f2NqVh/dx+Hk81K0sXwlw=@googlegroups.com
X-Received: by 2002:a05:6830:668f:b0:746:d8cc:4bb with SMTP id 46e09a7af769-74c704b57d4mr7794338a34.8.1757472716106;
        Tue, 09 Sep 2025 19:51:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757472716; cv=none;
        d=google.com; s=arc-20240605;
        b=a+N0OhsPAAz3XvJ89fKTY4006B//nBHfF2UQOfDL7M/cNj5eFd1VUiv01i6bYg9xxZ
         WVhG8q0yayQY+cRCWO9BxnYnRkx2KsCMFOKEjOG4v9QPrG0eWWppO58XvEZNgQ9eBbFC
         uS0sH5M+chiBsgHqkFsFjsMz6Onwz76XzsUZtvbhJL5gGSf5JAQE35PTnoo0RmkwlCRr
         C9cETKXtjkTrtveAqWhXMG7bYFUbbC3reQZn80F6ztvar7NzlOIRtPvLOLiFSqRzZJ8P
         yagdkvGQ/AS3Zft1ehN53sSXPiNr9Ck8E/HUptqZlycyiIAz1puBIFqJfCBcYrZ9PDxp
         PgWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=dgdemV9KYgQVQ+LAF8Hf9jr2yRR4WgfpLkTtMfHQpEY=;
        fh=dqnrqBs8j7UgGYJZcG2KPQ8a599sP40igXpxAAPcYto=;
        b=PfAd1C/DtrdgRY7mzjtPVbSSW+cQ6I7Jsf5uPSHnMsxWGziHKnmTXwvyXj6LzwJG4v
         nXKzAfDUzpWQ0O1ny9SbuhOwHGBJTkbXhgTQZQ/ETPEufINlBR03eNMZcvlOGdFkLhhZ
         mMQ5WcDNuxjzl0Zt4yoIdwAs6qQ/bw6sjb/rq2c+jIxqMquwXnoqQrgXbwhm47qb+M7q
         bsgqmdMXsi1GgFVvKgybhUdyb4++lcgBi9Hua0HMb5UXy6Vm+8J6S1o7VExjfMTka2K0
         bQ5nski1c6YDKBTAlofRKUhl9EKvkvicaebtRUMQf9BuQwSil7oDt4iAR0OV4JCIgoNY
         Xxxg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FtyBRJUc;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1035.google.com (mail-pj1-x1035.google.com. [2607:f8b0:4864:20::1035])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-745a33b347asi681661a34.3.2025.09.09.19.51.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 19:51:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) client-ip=2607:f8b0:4864:20::1035;
Received: by mail-pj1-x1035.google.com with SMTP id 98e67ed59e1d1-329e47dfa3eso5529235a91.1
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 19:51:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXglWxFbPQMMvwxpaolbV+UJmxWe2qxdKgZEYPbKX6DG349glnp2qhh5uEUY98s8hN0g1UQ5yCHuGQ=@googlegroups.com
X-Gm-Gg: ASbGnct7xLmFsb7c351D8yYnzSbdWAmJo98HFP7bY6xwVxCdH2laiLuPljDEFfV5DXG
	9CIEXe4+KHb4TnQq6gdz8r1VbrB2G/mk+QPuLpmnMkQ35ApWlYRvKxxkxjoFpU92asJzdfKJJoY
	3OQhMz22SRCs/+dsgIpdj/7eUfdzs3zhFmrZwE8fEP107KxU797iNVDzcOLFM1OOLL3c39yFgj8
	IFKEjbLgmSoMmsn85m0wFAZPQ4Ti5OXovcserSW3vPt4Dd39qof1nr/yIXhtu3TIBt6GN5eHKqS
	OrNod7u4/Yd9BeRwBOakYpKKyUqVtrV5C7Ht4iIWUXQxsOEX6jbe0zmoBBA+dtKwuq9niKbO6nI
	J/o8QZut5WvLqGW6b3b71p9nUcl3oSpSNtzVy
X-Received: by 2002:a17:90b:1dcb:b0:32d:3d64:a7d1 with SMTP id 98e67ed59e1d1-32d43f7704dmr16733026a91.22.1757472714912;
        Tue, 09 Sep 2025 19:51:54 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-32dbb313dbasm659051a91.5.2025.09.09.19.51.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 19:51:53 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id 2E07E41BDD49; Wed, 10 Sep 2025 09:43:53 +0700 (WIB)
From: Bagas Sanjaya <bagasdotme@gmail.com>
To: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux Documentation <linux-doc@vger.kernel.org>,
	Linux DAMON <damon@lists.linux.dev>,
	Linux Memory Management List <linux-mm@kvack.org>,
	Linux Power Management <linux-pm@vger.kernel.org>,
	Linux Block Devices <linux-block@vger.kernel.org>,
	Linux BPF <bpf@vger.kernel.org>,
	Linux Kernel Workflows <workflows@vger.kernel.org>,
	Linux KASAN <kasan-dev@googlegroups.com>,
	Linux Devicetree <devicetree@vger.kernel.org>,
	Linux fsverity <fsverity@lists.linux.dev>,
	Linux MTD <linux-mtd@lists.infradead.org>,
	Linux DRI Development <dri-devel@lists.freedesktop.org>,
	Linux Kernel Build System <linux-kbuild@vger.kernel.org>,
	Linux Networking <netdev@vger.kernel.org>,
	Linux Sound <linux-sound@vger.kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>,
	Borislav Petkov <bp@alien8.de>,
	Peter Zijlstra <peterz@infradead.org>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Pawan Gupta <pawan.kumar.gupta@linux.intel.com>,
	Jonathan Corbet <corbet@lwn.net>,
	SeongJae Park <sj@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Hildenbrand <david@redhat.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Mike Rapoport <rppt@kernel.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Huang Rui <ray.huang@amd.com>,
	"Gautham R. Shenoy" <gautham.shenoy@amd.com>,
	Mario Limonciello <mario.limonciello@amd.com>,
	Perry Yuan <perry.yuan@amd.com>,
	Jens Axboe <axboe@kernel.dk>,
	Alexei Starovoitov <ast@kernel.org>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Andrii Nakryiko <andrii@kernel.org>,
	Martin KaFai Lau <martin.lau@linux.dev>,
	Eduard Zingerman <eddyz87@gmail.com>,
	Song Liu <song@kernel.org>,
	Yonghong Song <yonghong.song@linux.dev>,
	John Fastabend <john.fastabend@gmail.com>,
	KP Singh <kpsingh@kernel.org>,
	Stanislav Fomichev <sdf@fomichev.me>,
	Hao Luo <haoluo@google.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Dwaipayan Ray <dwaipayanray1@gmail.com>,
	Lukas Bulwahn <lukas.bulwahn@gmail.com>,
	Joe Perches <joe@perches.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Rob Herring <robh@kernel.org>,
	Krzysztof Kozlowski <krzk+dt@kernel.org>,
	Conor Dooley <conor+dt@kernel.org>,
	Eric Biggers <ebiggers@kernel.org>,
	tytso@mit.edu,
	Richard Weinberger <richard@nod.at>,
	Zhihao Cheng <chengzhihao1@huawei.com>,
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
	Maxime Ripard <mripard@kernel.org>,
	Thomas Zimmermann <tzimmermann@suse.de>,
	David Airlie <airlied@gmail.com>,
	Simona Vetter <simona@ffwll.ch>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Ingo Molnar <mingo@redhat.com>,
	Will Deacon <will@kernel.org>,
	Boqun Feng <boqun.feng@gmail.com>,
	Waiman Long <longman@redhat.com>,
	"David S. Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>,
	Jakub Kicinski <kuba@kernel.org>,
	Paolo Abeni <pabeni@redhat.com>,
	Simon Horman <horms@kernel.org>,
	Shay Agroskin <shayagr@amazon.com>,
	Arthur Kiyanovski <akiyano@amazon.com>,
	David Arinzon <darinzon@amazon.com>,
	Saeed Bishara <saeedb@amazon.com>,
	Andrew Lunn <andrew@lunn.ch>,
	Alexandru Ciobotaru <alcioa@amazon.com>,
	The AWS Nitro Enclaves Team <aws-nitro-enclaves-devel@amazon.com>,
	Jesper Dangaard Brouer <hawk@kernel.org>,
	Bagas Sanjaya <bagasdotme@gmail.com>,
	Laurent Pinchart <laurent.pinchart@ideasonboard.com>,
	Ranganath V N <vnranganath.20@gmail.com>,
	Steve French <stfrench@microsoft.com>,
	Meetakshi Setiya <msetiya@microsoft.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"Martin K. Petersen" <martin.petersen@oracle.com>,
	Bart Van Assche <bvanassche@acm.org>,
	=?UTF-8?q?Thomas=20Wei=C3=9Fschuh?= <linux@weissschuh.net>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	Jani Nikula <jani.nikula@intel.com>
Subject: [PATCH v2 13/13] Documentation: checkpatch: Convert kernel docs references
Date: Wed, 10 Sep 2025 09:43:28 +0700
Message-ID: <20250910024328.17911-14-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20250910024328.17911-1-bagasdotme@gmail.com>
References: <20250910024328.17911-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=24675; i=bagasdotme@gmail.com; h=from:subject; bh=MXABwK0i0SCp2hQDcOsmX0P1tGCerPOJp0g33o7MdJc=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkHniifDTt+7KfV93lzj9/UmiHX46Vxep/YR+33Z39t3 TVtwyU2xo5SFgYxLgZZMUWWSYl8Tad3GYlcaF/rCDOHlQlkCAMXpwBMpIiR4Z9BbEfFppPy21Mr IpLu9zjPf3w1I1814cCLmzM05Rd27U9kZFhjOT/T7nby9gV/jrG7CvuWxxwx6nisFREuV/JNWc0 4kg8A
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=FtyBRJUc;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::1035
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

checkpatch documentation has pointer references to various style-related
docs. Convert them from external link to internal cross-references.

For reference to docs sections, use section names and reference
docs path as anchor text.

Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 Documentation/dev-tools/checkpatch.rst        | 121 ++++++++++++------
 .../bindings/submitting-patches.rst           |   2 +
 .../driver-api/driver-model/device.rst        |   2 +
 Documentation/filesystems/sysfs.rst           |   2 +
 Documentation/kbuild/reproducible-builds.rst  |   2 +
 Documentation/locking/lockdep-design.rst      |   2 +
 Documentation/process/coding-style.rst        |  15 +++
 Documentation/process/deprecated.rst          |   4 +
 Documentation/process/submitting-patches.rst  |   4 +
 9 files changed, 113 insertions(+), 41 deletions(-)

diff --git a/Documentation/dev-tools/checkpatch.rst b/Documentation/dev-tools/checkpatch.rst
index d5c47e560324fb..2ec288d845b81d 100644
--- a/Documentation/dev-tools/checkpatch.rst
+++ b/Documentation/dev-tools/checkpatch.rst
@@ -247,7 +247,7 @@ Allocation style
     number of elements.  sizeof() as the first argument is generally
     wrong.
 
-    See: https://www.kernel.org/doc/html/latest/core-api/memory-allocation.html
+    See: Documentation/core-api/memory-allocation.rst
 
   **ALLOC_SIZEOF_STRUCT**
     The allocation style is bad.  In general for family of
@@ -260,13 +260,14 @@ Allocation style
 
       p = alloc(sizeof(*p), ...)
 
-    See: https://www.kernel.org/doc/html/latest/process/coding-style.html#allocating-memory
+    See: :ref:`"Allocating memory" section on Documentation/process/coding-style.rst
+    <memory-allocation-style>`.
 
   **ALLOC_WITH_MULTIPLY**
     Prefer kmalloc_array/kcalloc over kmalloc/kzalloc with a
     sizeof multiply.
 
-    See: https://www.kernel.org/doc/html/latest/core-api/memory-allocation.html
+    See: Documentation/core-api/memory-allocation.rst
 
 
 API usage
@@ -287,7 +288,8 @@ API usage
     Use WARN() and WARN_ON() instead, and handle the "impossible"
     error condition as gracefully as possible.
 
-    See: https://www.kernel.org/doc/html/latest/process/deprecated.html#bug-and-bug-on
+    See: :ref:`"BUG() and BUG_ON()" section on
+    Documentation/process/deprecated.rst <bug-macros-deprecated>`
 
   **CONSIDER_KSTRTO**
     The simple_strtol(), simple_strtoll(), simple_strtoul(), and
@@ -296,7 +298,9 @@ API usage
     kstrtoll(), kstrtoul(), and kstrtoull() functions tend to be the
     correct replacements.
 
-    See: https://www.kernel.org/doc/html/latest/process/deprecated.html#simple-strtol-simple-strtoll-simple-strtoul-simple-strtoull
+    See: :ref:`"simple_strtol(), simple_strtoll(), simple_strtoul(),
+    simple_strtoull() section" on Documentation/process/deprecated.rst
+    <simple-strtol-family-deprecated>`
 
   **CONSTANT_CONVERSION**
     Use of __constant_<foo> form is discouraged for the following functions::
@@ -340,7 +344,8 @@ API usage
 
     The full list of available RCU APIs can be viewed from the kernel docs.
 
-    See: https://www.kernel.org/doc/html/latest/RCU/whatisRCU.html#full-list-of-rcu-apis
+    See: :ref:`"Full list of RCU APIs" section on
+    Documentation/RCU/whatisRCU.rst <8_whatisRCU>`
 
   **DEVICE_ATTR_FUNCTIONS**
     The function names used in DEVICE_ATTR is unusual.
@@ -354,7 +359,8 @@ API usage
 
     The function names should preferably follow the above pattern.
 
-    See: https://www.kernel.org/doc/html/latest/driver-api/driver-model/device.html#attributes
+    See: :ref:`"Attributes" section on
+    Documentation/driver-api/driver-model/device.rst <device-attributes>`
 
   **DEVICE_ATTR_RO**
     The DEVICE_ATTR_RO(name) helper macro can be used instead of
@@ -363,7 +369,8 @@ API usage
     Note that the macro automatically appends _show to the named
     attribute variable of the device for the show method.
 
-    See: https://www.kernel.org/doc/html/latest/driver-api/driver-model/device.html#attributes
+    See: :ref:`"Attributes" section on
+    Documentation/driver-api/driver-model/device.rst <device-attributes>`
 
   **DEVICE_ATTR_RW**
     The DEVICE_ATTR_RW(name) helper macro can be used instead of
@@ -372,7 +379,8 @@ API usage
     Note that the macro automatically appends _show and _store to the
     named attribute variable of the device for the show and store methods.
 
-    See: https://www.kernel.org/doc/html/latest/driver-api/driver-model/device.html#attributes
+    See: :ref:`"Attributes" section on
+    Documentation/driver-api/driver-model/device.rst <device-attributes>`
 
   **DEVICE_ATTR_WO**
     The DEVICE_AATR_WO(name) helper macro can be used instead of
@@ -381,7 +389,8 @@ API usage
     Note that the macro automatically appends _store to the
     named attribute variable of the device for the store method.
 
-    See: https://www.kernel.org/doc/html/latest/driver-api/driver-model/device.html#attributes
+    See: :ref:`"Attributes" section on
+    Documentation/driver-api/driver-model/device.rst <device-attributes>`
 
   **DUPLICATED_SYSCTL_CONST**
     Commit d91bff3011cf ("proc/sysctl: add shared variables for range
@@ -443,7 +452,8 @@ API usage
     lockdep_assert_held() annotations should be preferred over
     assertions based on spin_is_locked()
 
-    See: https://www.kernel.org/doc/html/latest/locking/lockdep-design.html#annotations
+    See: :ref:`"Annotations" section on
+    Documentation/locking/lockdep-design.rst <lockdep-annotations>`
 
   **UAPI_INCLUDE**
     No #include statements in include/uapi should use a uapi/ path.
@@ -472,13 +482,15 @@ Comments
       * for files in net/ and drivers/net/
       */
 
-    See: https://www.kernel.org/doc/html/latest/process/coding-style.html#commenting
+    See: :ref:`Commenting section on Documentation/process/coding-style.rst
+    <comments-style>`
 
   **C99_COMMENTS**
     C99 style single line comments (//) should not be used.
     Prefer the block comment style instead.
 
-    See: https://www.kernel.org/doc/html/latest/process/coding-style.html#commenting
+    See: :ref:`Commenting section on Documentation/process/coding-style.rst
+    <comments-style>`
 
   **DATA_RACE**
     Applications of data_race() should have a comment so as to document the
@@ -512,7 +524,8 @@ Commit message
     The signed-off-by line does not fall in line with the standards
     specified by the community.
 
-    See: https://www.kernel.org/doc/html/latest/process/submitting-patches.html#developer-s-certificate-of-origin-1-1
+    See: :ref:`Developer's Certificate of Origin 1.1 text on
+    Documentation/process/submitting-patches.rst <dco-text>`
 
   **BAD_STABLE_ADDRESS_STYLE**
     The email format for stable is incorrect.
@@ -534,14 +547,16 @@ Commit message
     The patch is missing a commit description.  A brief
     description of the changes made by the patch should be added.
 
-    See: https://www.kernel.org/doc/html/latest/process/submitting-patches.html#describe-your-changes
+    See: :ref:`"Describe your changes" section on
+    Documentation/process/submitting-patches.rst <describe_changes>`
 
   **EMAIL_SUBJECT**
     Naming the tool that found the issue is not very useful in the
     subject line.  A good subject line summarizes the change that
     the patch brings.
 
-    See: https://www.kernel.org/doc/html/latest/process/submitting-patches.html#describe-your-changes
+    See: :ref:`"Describe your changes" section on
+    Documentation/process/submitting-patches.rst <describe_changes>`
 
   **FROM_SIGN_OFF_MISMATCH**
     The author's email does not match with that in the Signed-off-by:
@@ -560,7 +575,8 @@ Commit message
     line should be added according to Developer's certificate of
     Origin.
 
-    See: https://www.kernel.org/doc/html/latest/process/submitting-patches.html#sign-your-work-the-developer-s-certificate-of-origin
+    See: :ref:`"Sign your work - the Developer's Certificate of Origin"
+    section on Documentation/process/submitting-patches.rst <dco-signoff>`
 
   **NO_AUTHOR_SIGN_OFF**
     The author of the patch has not signed off the patch.  It is
@@ -569,7 +585,8 @@ Commit message
     written it or otherwise has the rights to pass it on as an open
     source patch.
 
-    See: https://www.kernel.org/doc/html/latest/process/submitting-patches.html#sign-your-work-the-developer-s-certificate-of-origin
+    See: :ref:`"Sign your work - the Developer's Certificate of Origin"
+    section on Documentation/process/submitting-patches.rst <dco-signoff>`
 
   **DIFF_IN_COMMIT_MSG**
     Avoid having diff content in commit message.
@@ -599,14 +616,16 @@ Commit message
       platform_set_drvdata(), but left the variable "dev" unused,
       delete it.
 
-    See: https://www.kernel.org/doc/html/latest/process/submitting-patches.html#describe-your-changes
+    See: :ref:`"Describe your changes" section on
+    Documentation/process/submitting-patches.rst <describe_changes>`
 
   **BAD_FIXES_TAG**
     The Fixes: tag is malformed or does not follow the community conventions.
     This can occur if the tag have been split into multiple lines (e.g., when
     pasted in an email program with word wrapping enabled).
 
-    See: https://www.kernel.org/doc/html/latest/process/submitting-patches.html#describe-your-changes
+    See: :ref:`"Describe your changes" section on
+    Documentation/process/submitting-patches.rst <describe_changes>`
 
 
 Comparison style
@@ -646,7 +665,8 @@ Indentation and Line Breaks
     Outside of comments, documentation and Kconfig,
     spaces are never used for indentation.
 
-    See: https://www.kernel.org/doc/html/latest/process/coding-style.html#indentation
+    See: :ref:`"Indentation" section on Documentation/process/coding-style.rst
+    <indentation-style>`
 
   **DEEP_INDENTATION**
     Indentation with 6 or more tabs usually indicate overly indented
@@ -678,7 +698,8 @@ Indentation and Line Breaks
               break;
       }
 
-    See: https://www.kernel.org/doc/html/latest/process/coding-style.html#indentation
+    See: :ref:`"Indentation" section on Documentation/process/coding-style.rst
+    <indentation-style>`
 
   **LONG_LINE**
     The line has exceeded the specified maximum length.
@@ -690,21 +711,24 @@ Indentation and Line Breaks
     limit to 100 columns.  This is not a hard limit either and it's
     preferable to stay within 80 columns whenever possible.
 
-    See: https://www.kernel.org/doc/html/latest/process/coding-style.html#breaking-long-lines-and-strings
+    See: :ref:`"Breaking long lines and strings" section on
+    Documentation/process/coding-style.rst <long-line-break>`
 
   **LONG_LINE_STRING**
     A string starts before but extends beyond the maximum line length.
     To use a different maximum line length, the --max-line-length=n option
     may be added while invoking checkpatch.
 
-    See: https://www.kernel.org/doc/html/latest/process/coding-style.html#breaking-long-lines-and-strings
+    See: :ref:`"Breaking long lines and strings" section on
+    Documentation/process/coding-style.rst <long-line-break>`
 
   **LONG_LINE_COMMENT**
     A comment starts before but extends beyond the maximum line length.
     To use a different maximum line length, the --max-line-length=n option
     may be added while invoking checkpatch.
 
-    See: https://www.kernel.org/doc/html/latest/process/coding-style.html#breaking-long-lines-and-strings
+    See: :ref:`"Breaking long lines and strings" section on
+    Documentation/process/coding-style.rst <long-line-break>`
 
   **SPLIT_STRING**
     Quoted strings that appear as messages in userspace and can be
@@ -803,7 +827,8 @@ Macros, Attributes and Symbols
     and enables warnings if they are used as they can lead to
     non-deterministic builds.
 
-    See: https://www.kernel.org/doc/html/latest/kbuild/reproducible-builds.html#timestamps
+    See: :ref:`"Timestamps" section on
+    Documentation/kbuild/reproducible-builds.rst <kernel-timestamps>`
 
   **DEFINE_ARCH_HAS**
     The ARCH_HAS_xyz and ARCH_HAVE_xyz patterns are wrong.
@@ -868,7 +893,8 @@ Macros, Attributes and Symbols
                         do_this(b, c);          \
         } while (0)
 
-    See: https://www.kernel.org/doc/html/latest/process/coding-style.html#macros-enums-and-rtl
+    See: :ref:`"Macros, Enums and RTL" section on
+    Documentation/process/coding-style.rst <macros-style>`
 
   **PREFER_FALLTHROUGH**
     Use the `fallthrough;` pseudo keyword instead of
@@ -907,7 +933,8 @@ Macros, Attributes and Symbols
 
       WARNING: Argument 'a' is not used in function-like macro.
 
-    See: https://www.kernel.org/doc/html/latest/process/coding-style.html#macros-enums-and-rtl
+    See: :ref:`"Macros, Enums and RTL" section on
+    Documentation/process/coding-style.rst <macros-style>`
 
   **SINGLE_STATEMENT_DO_WHILE_MACRO**
     For the multi-statement macros, it is necessary to use the do-while
@@ -931,7 +958,8 @@ Functions and Variables
   **CAMELCASE**
     Avoid CamelCase Identifiers.
 
-    See: https://www.kernel.org/doc/html/latest/process/coding-style.html#naming
+    See: :ref:`"Naming" section on Documentation/process/coding-style.rst
+    <naming-convention>`
 
   **CONST_CONST**
     Using `const <type> const *` is generally meant to be
@@ -1018,7 +1046,8 @@ Permissions
     Typically only three permissions are used - 0644 (RW), 0444 (RO)
     and 0200 (WO).
 
-    See: https://www.kernel.org/doc/html/latest/filesystems/sysfs.html#attributes
+    See: :ref:`"Attributes" section on Documentation/filesystems/sysfs.rst
+    <sysfs-attributes>`
 
   **EXECUTE_PERMISSIONS**
     There is no reason for source files to be executable.  The executable
@@ -1074,7 +1103,8 @@ Spacing and Brackets
               body of function
       }
 
-    See: https://www.kernel.org/doc/html/latest/process/coding-style.html#placing-braces-and-spaces
+    See: :ref:`"Placing Braces and Spaces" section on
+    Documentation/process/coding-style.rst <braces-placement>`
 
   **BRACKET_SPACE**
     Whitespace before opening bracket '[' is prohibited.
@@ -1105,20 +1135,23 @@ Spacing and Brackets
   **ELSE_AFTER_BRACE**
     `else {` should follow the closing block `}` on the same line.
 
-    See: https://www.kernel.org/doc/html/latest/process/coding-style.html#placing-braces-and-spaces
+    See: :ref:`"Placing Braces and Spaces" section on
+    Documentation/process/coding-style.rst <braces-placement>`
 
   **LINE_SPACING**
     Vertical space is wasted given the limited number of lines an
     editor window can display when multiple blank lines are used.
 
-    See: https://www.kernel.org/doc/html/latest/process/coding-style.html#spaces
+    See: :ref:`"Spaces" subsection on Documentation/process/coding-style.rst
+    <spaces-usage>`
 
   **OPEN_BRACE**
     The opening brace should be following the function definitions on the
     next line.  For any non-functional block it should be on the same line
     as the last construct.
 
-    See: https://www.kernel.org/doc/html/latest/process/coding-style.html#placing-braces-and-spaces
+    See: :ref:`"Placing Braces and Spaces" section on
+    Documentation/process/coding-style.rst <braces-placement>`
 
   **POINTER_LOCATION**
     When using pointer data or a function that returns a pointer type,
@@ -1130,19 +1163,22 @@ Spacing and Brackets
       unsigned long long memparse(char *ptr, char **retptr);
       char *match_strdup(substring_t *s);
 
-    See: https://www.kernel.org/doc/html/latest/process/coding-style.html#spaces
+    See: :ref:`"Spaces" subsection on Documentation/process/coding-style.rst
+    <spaces-usage>`
 
   **SPACING**
     Whitespace style used in the kernel sources is described in kernel docs.
 
-    See: https://www.kernel.org/doc/html/latest/process/coding-style.html#spaces
+    See: :ref:`"Spaces" subsection on Documentation/process/coding-style.rst
+    <spaces-usage>`
 
   **TRAILING_WHITESPACE**
     Trailing whitespace should always be removed.
     Some editors highlight the trailing whitespace and cause visual
     distractions when editing files.
 
-    See: https://www.kernel.org/doc/html/latest/process/coding-style.html#spaces
+    See: :ref:`"Spaces" subsection on Documentation/process/coding-style.rst
+    <spaces-usage>`
 
   **UNNECESSARY_PARENTHESES**
     Parentheses are not required in the following cases:
@@ -1182,7 +1218,8 @@ Spacing and Brackets
               ...
       } while(something);
 
-    See: https://www.kernel.org/doc/html/latest/process/coding-style.html#placing-braces-and-spaces
+    See: :ref:`"Placing Braces and Spaces" section on
+    Documentation/process/coding-style.rst <braces-placement>`
 
 
 Others
@@ -1216,7 +1253,7 @@ Others
     DT bindings moved to a json-schema based format instead of
     freeform text.
 
-    See: https://www.kernel.org/doc/html/latest/devicetree/bindings/writing-schema.html
+    See: Documentation/devicetree/bindings/writing-schema.rst
 
   **DT_SPLIT_BINDING_PATCH**
     Devicetree bindings should be their own patch.  This is because
@@ -1225,7 +1262,9 @@ Others
     are applied via the same tree), and it makes for a cleaner history in the
     DT only tree created with git-filter-branch.
 
-    See: https://www.kernel.org/doc/html/latest/devicetree/bindings/submitting-patches.html#i-for-patch-submitters
+    See: :ref:`"For patch submitters" section on
+    Documentation/devicetree/bindings/submitting-patches.rst
+    <submitting-dt-patches>`
 
   **EMBEDDED_FILENAME**
     Embedding the complete filename path inside the file isn't particularly
@@ -1253,7 +1292,7 @@ Others
     The Linux kernel requires the precise SPDX identifier in all source files,
     and it is thoroughly documented in the kernel docs.
 
-    See: https://www.kernel.org/doc/html/latest/process/license-rules.html
+    See: Documentation/process/license-rules.rst
 
   **TYPO_SPELLING**
     Some words may have been misspelled.  Consider reviewing them.
diff --git a/Documentation/devicetree/bindings/submitting-patches.rst b/Documentation/devicetree/bindings/submitting-patches.rst
index 191085b0d5e8ea..7de63c5ce58fbf 100644
--- a/Documentation/devicetree/bindings/submitting-patches.rst
+++ b/Documentation/devicetree/bindings/submitting-patches.rst
@@ -4,6 +4,8 @@
 Submitting Devicetree (DT) binding patches
 ==========================================
 
+.. _submitting-dt-patches:
+
 I. For patch submitters
 =======================
 
diff --git a/Documentation/driver-api/driver-model/device.rst b/Documentation/driver-api/driver-model/device.rst
index 0833be568b06ca..7762d11411c5a9 100644
--- a/Documentation/driver-api/driver-model/device.rst
+++ b/Documentation/driver-api/driver-model/device.rst
@@ -35,6 +35,8 @@ A driver can access the lock in the device structure using::
   void unlock_device(struct device * dev);
 
 
+.. _device-attributes:
+
 Attributes
 ~~~~~~~~~~
 
diff --git a/Documentation/filesystems/sysfs.rst b/Documentation/filesystems/sysfs.rst
index 624e4f51212e63..a893e67f7fb2bb 100644
--- a/Documentation/filesystems/sysfs.rst
+++ b/Documentation/filesystems/sysfs.rst
@@ -51,6 +51,8 @@ With the current sysfs implementation the kobject reference count is
 only modified directly by the function sysfs_schedule_callback().
 
 
+.. _sysfs-attributes:
+
 Attributes
 ~~~~~~~~~~
 
diff --git a/Documentation/kbuild/reproducible-builds.rst b/Documentation/kbuild/reproducible-builds.rst
index f2dcc39044e66d..b0d273f871772a 100644
--- a/Documentation/kbuild/reproducible-builds.rst
+++ b/Documentation/kbuild/reproducible-builds.rst
@@ -13,6 +13,8 @@ The `Reproducible Builds project`_ has more information about this
 general topic.  This document covers the various reasons why building
 the kernel may be unreproducible, and how to avoid them.
 
+.. _kernel-timestamps:
+
 Timestamps
 ----------
 
diff --git a/Documentation/locking/lockdep-design.rst b/Documentation/locking/lockdep-design.rst
index 56b90eea27312e..c924dd4216c564 100644
--- a/Documentation/locking/lockdep-design.rst
+++ b/Documentation/locking/lockdep-design.rst
@@ -231,6 +231,8 @@ Note: When changing code to use the _nested() primitives, be careful and
 check really thoroughly that the hierarchy is correctly mapped; otherwise
 you can get false positives or false negatives.
 
+.. _lockdep-annotations:
+
 Annotations
 -----------
 
diff --git a/Documentation/process/coding-style.rst b/Documentation/process/coding-style.rst
index d1a8e5465ed956..4a17c60a9240c0 100644
--- a/Documentation/process/coding-style.rst
+++ b/Documentation/process/coding-style.rst
@@ -15,6 +15,8 @@ and NOT read it.  Burn them, it's a great symbolic gesture.
 Anyway, here goes:
 
 
+.. _indentation-style:
+
 1) Indentation
 --------------
 
@@ -95,6 +97,8 @@ used for indentation, and the above example is deliberately broken.
 Get a decent editor and don't leave whitespace at the end of lines.
 
 
+.. _long-line-break:
+
 2) Breaking long lines and strings
 ----------------------------------
 
@@ -117,6 +121,8 @@ However, never break user-visible strings such as printk messages because
 that breaks the ability to grep for them.
 
 
+.. _braces-placement:
+
 3) Placing Braces and Spaces
 ----------------------------
 
@@ -231,6 +237,8 @@ Also, use braces when a loop contains more than a single simple statement:
 			do_something();
 	}
 
+.. _spaces-usage:
+
 3.1) Spaces
 ***********
 
@@ -303,6 +311,8 @@ of patches, this may make later patches in the series fail by changing their
 context lines.
 
 
+.. _naming-convention:
+
 4) Naming
 ---------
 
@@ -594,6 +604,7 @@ fix for this is to split it up into two error labels ``err_free_bar:`` and
 
 Ideally you should simulate errors to test all exit paths.
 
+.. _comments-style:
 
 8) Commenting
 -------------
@@ -792,6 +803,8 @@ Remember: if another thread can find your data structure, and you don't
 have a reference count on it, you almost certainly have a bug.
 
 
+.. _macros-style:
+
 12) Macros, Enums and RTL
 -------------------------
 
@@ -932,6 +945,8 @@ already inside a debug-related #ifdef section, printk(KERN_DEBUG ...) can be
 used.
 
 
+.. _memory-allocation-style:
+
 14) Allocating memory
 ---------------------
 
diff --git a/Documentation/process/deprecated.rst b/Documentation/process/deprecated.rst
index 1f7f3e6c9cda9f..8ab538034a29b9 100644
--- a/Documentation/process/deprecated.rst
+++ b/Documentation/process/deprecated.rst
@@ -29,6 +29,8 @@ a header file, it isn't the full solution. Such interfaces must either
 be fully removed from the kernel, or added to this file to discourage
 others from using them in the future.
 
+.. _bug-macros-deprecated:
+
 BUG() and BUG_ON()
 ------------------
 Use WARN() and WARN_ON() instead, and handle the "impossible"
@@ -109,6 +111,8 @@ For more details, also see array3_size() and flex_array_size(),
 as well as the related check_mul_overflow(), check_add_overflow(),
 check_sub_overflow(), and check_shl_overflow() family of functions.
 
+.. _simple-strtol-family-deprecated:
+
 simple_strtol(), simple_strtoll(), simple_strtoul(), simple_strtoull()
 ----------------------------------------------------------------------
 The simple_strtol(), simple_strtoll(),
diff --git a/Documentation/process/submitting-patches.rst b/Documentation/process/submitting-patches.rst
index 5778cb9701e14b..387ccb760e1ff8 100644
--- a/Documentation/process/submitting-patches.rst
+++ b/Documentation/process/submitting-patches.rst
@@ -393,6 +393,8 @@ e-mail discussions.
 ``git send-email`` will do this for you automatically.
 
 
+.. _dco-signoff:
+
 Sign your work - the Developer's Certificate of Origin
 ------------------------------------------------------
 
@@ -406,6 +408,8 @@ patch, which certifies that you wrote it or otherwise have the right to
 pass it on as an open-source patch.  The rules are pretty simple: if you
 can certify the below:
 
+.. _dco-text:
+
 Developer's Certificate of Origin 1.1
 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910024328.17911-14-bagasdotme%40gmail.com.
