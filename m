Return-Path: <kasan-dev+bncBCJ455VFUALBB65ZYXCQMGQEX5GRIII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 02626B3B4D3
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 09:55:42 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id af79cd13be357-7e86499748csf759970385a.1
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 00:55:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756454139; cv=pass;
        d=google.com; s=arc-20240605;
        b=T/UN9sNp+WA98Km7VhP8v+T4WVB9D+Af3T2qnkGnYTBUHck5Ea/LcInHA9wchDkNYW
         l9WnST2fcfb3p7zPAMnCKWlFc81nKHakTHXvJY285szivzFayVII8qto1YBPmpUL1dJi
         PpWuzZ++RECbCdfh6zW3bNzZSgAu9ktwrjD+o6yEPPE5zn14bOe8MzgEAio7dz2ZfX22
         O67xf9Sgm/9fCei8WXoayqvWYK8L8YnKx/phpnMQhLMf1CN5y9ow7UbuB+2IAN1ivtZL
         o+REwqYC8O1YpvGVy27XMOKBnZqRv9YERYP3pq8tsLjiuNg46HN2k0CbjPE+BC8bJqpY
         Z6uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=VTo/d8EVPdFEjZLoLQ9xjw58Pc9XzVMk1+GqZLqrdzA=;
        fh=aciFAt99DaI9Ws+zYGYJ3IGQCCwwlZPh3x1ctX7DHbE=;
        b=jJNFSsVwnLr0Q75Po/y/GB3y//PikxgO1o2caA2NX8ZAlty70j0UIB3jtJ4Ckcpkgg
         Tc7KL4iTE3CPY0aWeddP/qy8vkQAQnwJ/zXOR3mBiOe8jhw4vakq00uFVKen9nJUyDDz
         Dhkv/J+dM/fbqoC/fwyK92e7zcHJh+zkBPA2+XxeQ6JT+ijlgvueIZzjaqBiACPKBcYc
         H9MsBd8w2vfNeuQwvvIbLHr07de65Db4ZHtOjOGd3gIuwJ1GeAJpb0rM9cVI0d3Yrpmu
         fI7FiaKvXK5HU9LFMAhltHidSRXOIhn/byLHzb0RmtNQ9l2PZN2BP3wS1uaEpqfLwQhS
         6DKA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UUmhIgFK;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756454139; x=1757058939; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VTo/d8EVPdFEjZLoLQ9xjw58Pc9XzVMk1+GqZLqrdzA=;
        b=gSAxs2LOXZWdVKv3OpA9dRfOKx4KPagJF5zoYmU9nm4hZ6DvEBpiSy8VrZoPlOMP4R
         SsFeDC7tQ8An/kioczYhYK+V7B2Jg3reMmfeD2gUuIY8uP8hPwjZ6ApO/+Sb5kEDO6J6
         9iTEqkKgKTsKmp4vgEKTU7LXEv08aS6n8kHf6Kj1bYM3GqgaJ1gtDpGmCk8V4k4c+yzk
         xQMo0QsiRMSEHMTZT1En3Be3HU3o6+gKP5Lk/dM33xt0BYHsYnHCbstNseSWpgJ1OO91
         X/HZLTpO/K6wsf+jWZoHEQxvL+LN48JFPuYyWuKgnlFT8wx4UnphL1pTLenOCu+ywR4n
         dY3w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756454139; x=1757058939; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=VTo/d8EVPdFEjZLoLQ9xjw58Pc9XzVMk1+GqZLqrdzA=;
        b=Vv2EbXpT6DhRWApX0Fx2mKerkOQq9SQh/S05jPxVvS6FqKqDOCQ5DhlNE1ubmJUNd1
         wFF3NwYmM/bZlzs01qpZowtXeIUGjGZIaeeSCSAZ56yQ5AIxXIRj2VXJc+c6rXFkeRVc
         5c4z/H3WRjPAvYP9NUJEljpYwZV5E/WlmRsKAHZXtio23HjKGzlDoZ9YhY831lAGYNxK
         LckwDjQMCZUk2lPC6TScnz+VXcSWPXxaJlCxsmf/DmZcMyCM5LXPSZLDn3r1rFAk5s8c
         yaUM3dUbVBB2/+PiW6Qoi+ZcwVe0gNOG1FaFKNtUj3ded7vAPecXkaRYHmV9A+VMfvAT
         +veg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756454139; x=1757058939;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VTo/d8EVPdFEjZLoLQ9xjw58Pc9XzVMk1+GqZLqrdzA=;
        b=X0Czoa0/pTUsn7oWeexhtNRH8tqu5HMERJ0dnUh7L8XIoxGw9mmMLx50O29+rCkeIp
         cesgNaMyo7eDXE0RjR+qFeARUBqt0VMW1hl66aQP4FeaINFnF32qNyS1m40kEj/tNzor
         crH3inxDUJl5erxoQaOqDSsAy3Nhkf77FbcgOups+qQQenzZCtP31gh7SqSYJXuP6e6e
         OePy/VmTD5tm1N4VfqpwGB1kMk4HdFfvy1ibU4E2fYhlmNpmfBJiRLG66ORaZsBgKUla
         Bgl/BUWURzWx+zpEuvpEZx7xteSJunb2Visbe0QAcxvXzZciEUqGMcMRiTarUpoFf2Tp
         UfDA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXs6BClqAsr6o3SEVDQ2xf6ESYWyE+6ah+jTWRJ2RatyI77119o6tgLKKPWU1l0lhuy8Q9jqQ==@lfdr.de
X-Gm-Message-State: AOJu0YwwovCFabyaeCPO5Q8iTxATqeFKvRZWxpZqbxI7WsQTY9A2Ofya
	6PZgjLuRljkum8mO/hTWmUW7rcDqQQ3px25ON0u3vuXxmDE5ePmDsGxs
X-Google-Smtp-Source: AGHT+IFEaUSbuahYY2600JW1zXauXuYgyNJNkOf73QvDHYcmU8qHnOAX4shepyczQIUVn1CcjjMk8g==
X-Received: by 2002:a05:620a:460c:b0:7fa:2f62:f7c0 with SMTP id af79cd13be357-7fa2f62fa17mr535824085a.5.1756454139453;
        Fri, 29 Aug 2025 00:55:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcwW9YhkP7syn/wRgovTug+Q5nCRJ6BR2dC/b22HAj0kg==
Received: by 2002:a05:622a:5c0d:b0:4aa:fbf6:4242 with SMTP id
 d75a77b69052e-4b2fe563411ls16892841cf.1.-pod-prod-00-us-canary; Fri, 29 Aug
 2025 00:55:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWR9x8yFjqNXEnJW6MXgQlpkZ1AuYJYrvNk3XxuAmPCEgus7AwReabCkpjTYZ7+rFmCGJEaM7xj0rE=@googlegroups.com
X-Received: by 2002:a05:622a:44:b0:4b2:9a53:7c10 with SMTP id d75a77b69052e-4b2e76f7ee3mr127522691cf.23.1756454138773;
        Fri, 29 Aug 2025 00:55:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756454138; cv=none;
        d=google.com; s=arc-20240605;
        b=G8Oc905cymazhLuY6SwO3nCco9kPvPnJ0FTpUiTvTJOl8toPeoleiQAu8C6VlBr8uq
         sPOIrcYA+9YUDyus+bNMrRj09G1eZgKhzbs74wuZnoxNveSdYbuPNWkTtX9Mp5V/Vn6M
         qTDSe4FWZKbHgqz20OnIn/LdrrrRcKFTRo+b289AJ7HPKHhbliFDofkn8/VpX2Gb40w5
         G6RAN3ab+ThhM0HnKZD+Bz310Arkv2+gdp+GFmf2hMya4TR3Ax1M+3k8urXpXAGfnGVt
         rjotfAg1RuoWfVBKwKW39NQO8mI1GsbyqO1G8j2eCS6MssXajc0nzQhJpyRyytIVdLQU
         JNKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4+SUGCH8uEjWgwJ6PdsO74F0lOA4arnp0TuRWyoM63o=;
        fh=ugJA19uUYz5D3fcg46t2VIsSlCh5XBx2K/Yf+irXx4A=;
        b=YHmyZ28QjYU5Qfmf75qSH+vmTbxaW1RHRrdJRyoENS3W0i16kinWxU1ANMG8oiQNPt
         tHadt7EoDGf1iZnof27+eNpeuoHCgWVIx353aPmeWvNXlughUNzvC7q6Qg4u+nD+MjQe
         j5k6VaIH1tFAe0+tVUOeeh8NAg1VWL329B/eOsS839240Up+NyKLemkQTwq2VfvoPvY+
         sPmCPpLh5xgsDVr9WvrKiHZbKMeWmEre7gq87I7q10uBWIidOWzmF981qztjm2hAzwoN
         p4PQAdid5rkeuaOYZ5da7iPbzeCwy8/TYn2YDvWY9LtP1aX2uUSyScjYGvHiQxoBOqkx
         GLBw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UUmhIgFK;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x529.google.com (mail-pg1-x529.google.com. [2607:f8b0:4864:20::529])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70e57e1a4d6si672416d6.1.2025.08.29.00.55.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 00:55:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) client-ip=2607:f8b0:4864:20::529;
Received: by mail-pg1-x529.google.com with SMTP id 41be03b00d2f7-b476c67c5easo1293989a12.0
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 00:55:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWmPwjLACki5F7JxKBkhc9O5a/1LIG7yVlMM7pXqLjg6goovmJPbSGNr5CFLWdnpkmK2DYeU3MuLDQ=@googlegroups.com
X-Gm-Gg: ASbGncsvboiGw/+WhmWVH5yl5lLZTyWk7FUJruWz3B37H6KVSY8WXS56zj7NvfHEDwr
	MGdNq4CvULOm44//mkfPpz3vvHXAjuZNla2XugKAeWKD4XR+u7JsE62Av6nJaTh9G9VOePHli3h
	DLXxsIi0rqqH3HX1TjXXrClqSscy3ETLb0AUDyutGic3luK9UPxmu93Rn5zUMB7pQoXXRJ6jZyf
	3HTvl4tsU8RYfXvwXSAq1/q3hC9F67X6+I6x4ecHXIdXxU9rTfcHLHSpQf6OWjJXACf9OLtrHen
	6mk5FVAwWxAoIby0M0k3ZX0XBOzCqI9q0kqHGbZbURN9z7XEvgq88CqxKIya3T3EAXLreLqDKan
	KDoWlJxcNqeLFrUCz6Sg0BNh8moFdopbsmSWP
X-Received: by 2002:a17:902:ea12:b0:246:7de5:6e92 with SMTP id d9443c01a7336-248753a2789mr172792715ad.2.1756454137684;
        Fri, 29 Aug 2025 00:55:37 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-249065d6ea7sm16241905ad.135.2025.08.29.00.55.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 00:55:35 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id 5F71C44808E5; Fri, 29 Aug 2025 14:55:27 +0700 (WIB)
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
	Linux Kernel Build System <linux-lbuild@vger.kernel.org>,
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
	David Airlie <airlied@gmail.com>,
	Simona Vetter <simona@ffwll.ch>,
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
	Maxime Ripard <mripard@kernel.org>,
	Thomas Zimmermann <tzimmermann@suse.de>,
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
	Liam Girdwood <lgirdwood@gmail.com>,
	Mark Brown <broonie@kernel.org>,
	Jaroslav Kysela <perex@perex.cz>,
	Takashi Iwai <tiwai@suse.com>,
	Alexandru Ciobotaru <alcioa@amazon.com>,
	The AWS Nitro Enclaves Team <aws-nitro-enclaves-devel@amazon.com>,
	Jesper Dangaard Brouer <hawk@kernel.org>,
	Bagas Sanjaya <bagasdotme@gmail.com>,
	Laurent Pinchart <laurent.pinchart@ideasonboard.com>,
	Steve French <stfrench@microsoft.com>,
	Meetakshi Setiya <msetiya@microsoft.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"Martin K. Petersen" <martin.petersen@oracle.com>,
	Bart Van Assche <bvanassche@acm.org>,
	=?UTF-8?q?Thomas=20Wei=C3=9Fschuh?= <linux@weissschuh.net>,
	Masahiro Yamada <masahiroy@kernel.org>
Subject: [PATCH 04/14] Documentation: amd-pstate: Use internal link to kselftest
Date: Fri, 29 Aug 2025 14:55:14 +0700
Message-ID: <20250829075524.45635-5-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20250829075524.45635-1-bagasdotme@gmail.com>
References: <20250829075524.45635-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=889; i=bagasdotme@gmail.com; h=from:subject; bh=YCjSy3OR+PtbNsOx3d7dblyTwJjnDEtFBwBCle5X25g=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkbY14qPYlapHXxetwsqb0JS9jb7/0/73aj6M+zsn/7f 7uJBK+t7ihlYRDjYpAVU2SZlMjXdHqXkciF9rWOMHNYmUCGMHBxCsBEJPkZ/hloBmcs7pqXLvRo 3uW3yzpsL08refrBOejE1FfXjopF7nZk+B9pJzZFXlK9u2zWB3XR7Keu63hWz99heLTAzXSF0Y1 5YmwA
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=UUmhIgFK;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::529
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

Convert kselftest docs link to internal cross-reference.

Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 Documentation/admin-guide/pm/amd-pstate.rst | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/Documentation/admin-guide/pm/amd-pstate.rst b/Documentation/admin-guide/pm/amd-pstate.rst
index e1771f2225d5f0..37082f2493a7c1 100644
--- a/Documentation/admin-guide/pm/amd-pstate.rst
+++ b/Documentation/admin-guide/pm/amd-pstate.rst
@@ -798,5 +798,4 @@ Reference
 .. [3] Processor Programming Reference (PPR) for AMD Family 19h Model 51h, Revision A1 Processors
        https://www.amd.com/system/files/TechDocs/56569-A1-PUB.zip
 
-.. [4] Linux Kernel Selftests,
-       https://www.kernel.org/doc/html/latest/dev-tools/kselftest.html
+.. [4] Documentation/dev-tools/kselftest.rst
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250829075524.45635-5-bagasdotme%40gmail.com.
