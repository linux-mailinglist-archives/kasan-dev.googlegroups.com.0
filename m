Return-Path: <kasan-dev+bncBCJ455VFUALBB6OLQPDAMGQEPMP2XPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 558A9B50B4F
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 04:44:11 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-329207bfba3sf3027795fac.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 19:44:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757472250; cv=pass;
        d=google.com; s=arc-20240605;
        b=GU7CneHHn70AdLk+2vNk6RVA47XbFpdFSYlDuSe9YoKJsFGvgFhi4lO48IjBs8P/g3
         /9ALtc1WX0Bs/D7fHPLFS6BBnGneuXZtTd9LSaSv5Qd9PQpNBgxzJV1t/gzF0ay5ZGH6
         8lwy1FBh3zXcP3AJuDScmsS1OMGFkniUJf9Lm0xfWJkDM3ZtAL5x5IJqcDBE5EByJujE
         8qnijGReZlFkEMFfo6KQU39ToX5blrGBdl6srK6YRLYwaGCTyVmxxGk3HBt9qu0Msayy
         iu7pGpz4DL4xhpj878Ucwl1ISiLbb4Y+jlSl0wIVjVzaD61KJ5Of2iLTyzDL16roSRLm
         chHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=+guAxAwhDDXmoHqgttLqHRFbzdJRefXvwjuys9Qqng4=;
        fh=Dyg+uEc7zfVcLHlAxI4Cknba4w+CWujpU9np1Bv51sY=;
        b=F/czcg2jYZrC0/E+r3LsA5oTLer1ZzH80HzHskNM66d1A5Ahw+fBUHSa8pltAfVfXC
         lYBqW1m1lsccQLDgMmR2ggoUgUfeMdcXhfbOaIyLqzEctpdbbSoOVkV1nLnimgv+3ygh
         HDoPAtqIQNfo0m9Jgm4xp4S90jlvrsXYX0s9VyTx6C2I6mBxThHy52UuhrhxByVxMJoX
         jCthPimihFFqW5RQAfMxONt67bLHhM7GAh3RC3Gn0WU3Dn0azWZD29LKoQuXn9QvWLGx
         akj7WOTNCm2GvEZmocEDYB/j0jsrq0DZPKrR8zQjDi6DtOSrYTNDbmu5pA84STTU0e0R
         4Xlg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DjWgKPXk;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757472250; x=1758077050; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+guAxAwhDDXmoHqgttLqHRFbzdJRefXvwjuys9Qqng4=;
        b=raLScY/GBy30E3kJQwmLYiWSrKr7teLw2YhYrrrsuEpSGVnPXyamYT4KsPnhEzHwo+
         SZPK3xydz5zMceBjaovbF2wKWM5/TOyCFBxVycNhMSuZhngzS0ICsiP+OzcraoQaB4k0
         U0EPhPa94+NVlG+ZyEngW7LKdb9Eq2ns4kgmBPWuXNBjA1FCiDsu/W9PHnJV1swVcHoG
         FjQI88cO3HNcDXTCiR9cW/rh/eWGSxjRPb9YNLgboxdqwB9jfTmn5EBRn9S2TW1X2WCo
         GLNVlFmbG/Swa4GIU3hDvF/SBECwuLMIIzhsYU50vhBALGWR7dol+y8Y4jRB7ScDKZup
         WXug==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757472250; x=1758077050; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=+guAxAwhDDXmoHqgttLqHRFbzdJRefXvwjuys9Qqng4=;
        b=C2x55xQQfwg0fwk91rqAWtpLScjUbcfPGRdKKFPPzflkKw0GVfeVrEbal/vgZENqUq
         Dwl65qcDbkWk5PfcZgtLwczfq1g9wFHyTEXGVUza4vSlku4xv7shSXdU4KH1W6zAvdrT
         PGiHrugNvBz4zeQNZoPrBZl8k3feXmw2FwuCbwt3P8h1iMp67EhuLNL+w/jAyA+YOIpU
         Hee8jxOfvzMntptx4pYdwt6godjO3q3ejaniqMqUfmNgH1hDEzWqzLcQ4Ukp0CqYFj9W
         79wt9YRJ5CkJInZiRmtCgpsEjUx5rWbXyj0d0Xu8105fkZU25c/o7dBBYfhxuRLGZYzr
         5vAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757472250; x=1758077050;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+guAxAwhDDXmoHqgttLqHRFbzdJRefXvwjuys9Qqng4=;
        b=RA8Hr+d0OEVLDp8daodhn20DENJQeJ2wLiGeI+Lq4yU31tukS8QomuYxylrf664CgL
         GYiE6GFvwE5hAm/JCQ+aTCc2K9eqnr5M6CNB+9QMc56pKWjIReaVStoH1J4UoyhI/lPt
         5Nm8WcBe+9sJR/wHbPG/hWGZECLRNCT9FvwNz8uwe3+wB4m+y/Ii9vvhfXWzmu4uPR6T
         9SolO5iT1bi47eTVXD7gsvOiiROb1NbBg7zJV/BqYfzYeGt+MsPYKe7ffFcfUtO1L6qD
         RXrjr9lbaoxEpK8Hzb9LsWe0v/LA8oVUHdJ4PJq+aqXG9j9iHDFeBmMS7EFRFR5DVXdR
         ZHdg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVFYepLccmw1XNhN0OIhuwflZ0A7fiGYDxOZ4KztxZUDbhRsFiGE2q3oTL+EaVCYqLVRfp/lw==@lfdr.de
X-Gm-Message-State: AOJu0Ywkw3D95Jw7RwNp0lsjhqTxBftoYOIupvpKcVkLvTzHMRzRDFaD
	ZsdrstjUK4FOaiNBFy6B/S2YH1CFNFJ3s5J9pkqXHm3R4FqcPfInjZxD
X-Google-Smtp-Source: AGHT+IE5qNngPZ7WuoQNzs/f7ZL+kbWq3w4H22j7v2O+KORpmXe4fdOqNnH4mRx50DgXoGokz2lzSQ==
X-Received: by 2002:a05:6870:2042:b0:307:3d5:713f with SMTP id 586e51a60fabf-322630a52aemr4988577fac.19.1757472249964;
        Tue, 09 Sep 2025 19:44:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcwgHqrGM2EcLC3CAFwshBhLMYZWVGckcJ9ZwbV/LxktQ==
Received: by 2002:a05:6871:291a:10b0:321:2522:a7af with SMTP id
 586e51a60fabf-321272b45a0ls2167220fac.2.-pod-prod-07-us; Tue, 09 Sep 2025
 19:44:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWb8KVZOvc7xy7Vp8TK8RJD5P7Wbu5FOt2Ycy5gFuOkdNx2DO7YXc4le4BtpiMugHt2couH1O6CU84=@googlegroups.com
X-Received: by 2002:a05:6870:b4ab:b0:315:663f:4056 with SMTP id 586e51a60fabf-3226274123emr7149882fac.4.1757472249038;
        Tue, 09 Sep 2025 19:44:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757472249; cv=none;
        d=google.com; s=arc-20240605;
        b=ceEvOHl1o6vmFsGm288EUWOwago5DdHFZjFUI9u0oZRfn8soGNYz/c78PqF7/HL6mX
         Vx4JMc+VgYjCGimQHFwOm+A/6BANOjx9uqffxl7+Wtb079+34SVaEQyEth87FRk+YJn5
         tE8f+4LnoADh8etZBn3084WWMgcNMdTYe4g3Uc7cYioEwAOC7Nd4dacunP6egHMgCc6M
         ZU8Izb2hvHHzIdU+xStjPbEnGyh28jKUWOYsYBmNWWL4bDcgMdLgGk8NOP7X2HDheSct
         revQUlYYqMqm5dYyXd4pb45XUmHAQv6DOEFIT9E3f0tTmsKkFjF/zJrmNuorIAyuhWV5
         noxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=mQcUO3MMNiHKjyp0GXG4A4uvsTQgAsYSLBA8ucpISkE=;
        fh=eYGBmLsl0Cp8hWzCQfSoER5lgwxGwg0/f4Z9kZyXGIE=;
        b=TtHAYROgRIFdaAF+o4grPr+9cWr/EdJcMHCsEO61QD5iROgxtxzup+lTmLIMKxBy2Z
         KmCMDjakidLRD6XZOGheJ2gkrGToTvdOGV4zN9dFPuGTWyNfB/sJpqgagWkt/7s1G4/9
         PraEFcj2MpAV2WPPDX01DGLAEby//RfSnQFLqeOlQfpHSLUs5uqEGm+IRXujCtCRt9U2
         51xze2SjqLlpda7gWKrD93ezLlG5CO8lK45JJ/0lPocuBwzGgpcLsOJ7dQFJ9MYsEZbP
         Bm0SD0uIQnh0ur5u4E+7OICk86HZbV3TxL94ofhwtNzfhlduUgyJ7vuEmGFHaAf2tcwz
         kBUw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DjWgKPXk;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102f.google.com (mail-pj1-x102f.google.com. [2607:f8b0:4864:20::102f])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-319b5da4be7si818198fac.3.2025.09.09.19.44.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 19:44:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) client-ip=2607:f8b0:4864:20::102f;
Received: by mail-pj1-x102f.google.com with SMTP id 98e67ed59e1d1-32b70820360so5044454a91.2
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 19:44:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCViYx4bcozw9ygi51Y+yX8QT3JaBDZx8rUsq+BL2W4CqOZcRjvGvSbBrHQVobvyQGjHT3SlbrOyoik=@googlegroups.com
X-Gm-Gg: ASbGncv63m90K1R86FD5hoqgFkzUZlLertgPJDpZOaBJ2zn/GzadCd7A8VXE08wvORl
	CrCn9qIqV4VIaPeLGyhCp7VqyMG7sn3U4wPNiDLwXSvCRci0zF3hMxyRxKF8PrMaJsj9Dni8nhP
	Sfive+D5aLcNnZIvUS93LZTnmkJmS2l7G0UufX5trZ0hVTIeLgeJ2ikDQwezWPzGowJp5OvAjih
	LbsusC9LwtihHP/+ZtQhlT9621IbgimSzf5LttGeDWcw6xu90uUDr/JTGJMC3ZKtZNHbSN891AD
	YbiuD5IbcTjmbKj4i91kD+teuivVQlT3Ja1USolJ0VM2drV/fLvm0aoRAgIGpRudZVgILJgi3lt
	pqj6K072VmUCTmUD/hTi1XOy1Fg==
X-Received: by 2002:a17:90b:3e83:b0:32b:dfd4:95c9 with SMTP id 98e67ed59e1d1-32d43f65178mr18795979a91.23.1757472248435;
        Tue, 09 Sep 2025 19:44:08 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-b548a6a9cbfsm1032315a12.30.2025.09.09.19.44.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 19:44:03 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id 158E941BDD48; Wed, 10 Sep 2025 09:43:53 +0700 (WIB)
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
Subject: [PATCH v2 12/13] nitro_enclaves: Use internal cross-reference for kernel docs links
Date: Wed, 10 Sep 2025 09:43:27 +0700
Message-ID: <20250910024328.17911-13-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20250910024328.17911-1-bagasdotme@gmail.com>
References: <20250910024328.17911-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1391; i=bagasdotme@gmail.com; h=from:subject; bh=evrdLEAoXKuQzTljW81Kh3KyWLApG8gUObVzJ2YlNgE=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkHniiL9usWFB1WvT+NSavLIanh+698vZJvp5Iqyn5cF Oeb1Xiho5SFQYyLQVZMkWVSIl/T6V1GIhfa1zrCzGFlAhnCwMUpABN50cHwvzL4D8eTgyE89fse HlBVStE02WjOOvl23fZ49/PHUnNONTP8FYh3YzzAeWbK5vj6FqvtSXp3M3+Vxhz3fMrXXv7oQq4 HPwA=
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=DjWgKPXk;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::102f
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

Convert links to kernel docs pages from external link to internal
cross-references.

Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 Documentation/virt/ne_overview.rst | 10 +++++-----
 1 file changed, 5 insertions(+), 5 deletions(-)

diff --git a/Documentation/virt/ne_overview.rst b/Documentation/virt/ne_overview.rst
index 74c2f5919c886e..572105eab452b2 100644
--- a/Documentation/virt/ne_overview.rst
+++ b/Documentation/virt/ne_overview.rst
@@ -91,10 +91,10 @@ running in the primary VM via a poll notification mechanism. Then the user space
 enclave process can exit.
 
 [1] https://aws.amazon.com/ec2/nitro/nitro-enclaves/
-[2] https://www.kernel.org/doc/html/latest/admin-guide/mm/hugetlbpage.html
+[2] Documentation/admin-guide/mm/hugetlbpage.rst
 [3] https://lwn.net/Articles/807108/
-[4] https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html
+[4] Documentation/admin-guide/kernel-parameters.rst
 [5] https://man7.org/linux/man-pages/man7/vsock.7.html
-[6] https://www.kernel.org/doc/html/latest/x86/boot.html
-[7] https://www.kernel.org/doc/html/latest/arm64/hugetlbpage.html
-[8] https://www.kernel.org/doc/html/latest/arm64/booting.html
+[6] Documentation/arch/x86/boot.rst
+[7] Documentation/arch/arm64/hugetlbpage.rst
+[8] Documentation/arch/arm64/booting.rst
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910024328.17911-13-bagasdotme%40gmail.com.
