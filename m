Return-Path: <kasan-dev+bncBCJ455VFUALBB36LQPDAMGQEHR4QYJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id B92F5B50B3B
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 04:44:00 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-7248ed9f932sf78255266d6.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 19:44:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757472239; cv=pass;
        d=google.com; s=arc-20240605;
        b=PZnBajfmfUL+LtrdWkeN+DXu3lzMiC+QiEy8Ss83Q/zVXwkxnJ3uefYXLgWZ0eUhTz
         Zewny4AKfeXQiGZRCCcqbNQ4mTFhZ9m7EyS1vlGyNakDmSMOtELMh/80gIf5tjpoLm84
         7gkMwTNdpSYDQ/xB1Xrhzwy2jK6JISpPL3DupukWYUKd4qziHeRrkbxPAmtGoiS4KiZ6
         FcacAqPOum+RRMobnR5LeRJoKqX4rLU3lsPTLO4X8nC1PxJZoHj1fE7m58wAJDOilRjs
         C/4S9Lx7Qi14F4tjlnzO6FG7eQ+JwYpCR2rYqU3cB+i0a9igaZWDmp+b8oLu+/9hTbRa
         hkIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=yHeDYMNrsJdHIBqMpiuZBUNGmHPCeeuQo7ubmslyMuk=;
        fh=7YO12h3r1jmpxTDnjUV5bfx/5XNpetdbnig7R1tuYXI=;
        b=DWbNjvGqcQJELMaCvBrb0vqqabXu2IuQwt41A0pdtNPcNTBGVVOgtoD/WI5xwyYlTN
         jq6bYqSaAbL26hLCLDxpkZX7d8q9zxVbMEVfqGWahXPAzX4Za2CwwNG4ihEa+yBR1d3a
         rjj7bn0wkmp7+Z3HDSyqeHTszAlWyPIoL2jvdR5fcSY/nO5kV/QQ6emnTB9MqEswvHyY
         w1okNAxCSEqg7bA+bvh+Fk4djzZg58aIAl9/XDg4RUbDVhIi/bBTHrvrRwL15ysJRfsG
         X3UU6M8CtEnprSw5OT4h6MJAslTWRtMYEX9IwfL/VoPuJngOcpfnsP/SKrWcAq79Gjg9
         P4AQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CD5Eofcu;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757472239; x=1758077039; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yHeDYMNrsJdHIBqMpiuZBUNGmHPCeeuQo7ubmslyMuk=;
        b=Us9n/hvaPvaLFGyMo6bnQf7BcsXDxcgHOBZjqwoSxcC6nogvmIQTAa/dg0YEkL0maP
         0wUFOmtbpMPzlh3V1+M16ojxe4S7vyifk4E9p05CrNYlNcX3QjndUGVFWCY5YvkHGU/S
         jLc1f7D3EtOE7OTjBhmymdzmSfjwdXU2XEVcqHIxt6QE2z9DBTut5aqlny9RGYQVlWCL
         U3IcDTfN+4Ce98x8kxuBM2k4gHzT3gZvZGngPaIIzwXzssNMKkBMOHF9hr4TxRNrOB4M
         uy6mlVA+yNONMxqQ7Ljb5HTrMqlF76siRsEpgq2szZEyyEAbgQHgvygFi9oyJBBf3p3s
         cceA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757472239; x=1758077039; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=yHeDYMNrsJdHIBqMpiuZBUNGmHPCeeuQo7ubmslyMuk=;
        b=JcnqkFUpx7kZ9928yYokH81VJ+Ayp4WRkJ5t6+pzEbUwVzucAvoPU8fT7anfYq3rzM
         6x2ZfSLfmX5ARxY46s1pHCpylLjctskYREvjuZpuEjVzYM9Y9GmLYoNgwwZWdjljIIQ1
         UbY2xqR8AuDPp+penx1zprmVrduaRA3Wm1XK8M23Bb8oXQM4VGcraZ7tsU84jgqyNI4D
         45Gonr/R8zxTPqsZ+1Klj+VtL5MzMhpmTiUEYXzWaTnBhlzQnOH+3g/NC9U5V8W/Vm3U
         TDxW/kx9OyOzhO90nb4lKc55jW94e19n/gH6/2LDJMl6mcaCrfTa2wfv6o3nQkiTfb49
         nSOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757472239; x=1758077039;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yHeDYMNrsJdHIBqMpiuZBUNGmHPCeeuQo7ubmslyMuk=;
        b=Zvn+gekGaad3n5qIPFGJlGBBNLVhFu9uUUbdDiu/hJIbfFNZhvvES5OZG6cW8ksYq+
         /WkEmuyK0PCypOSCls2okIZXt9Xq1VTiVI+FBCHRgHnQbp1DjCoDZiHdlsb0YROw3qim
         wtcmbyItE/WfN3Z3gp7hYpvnOr32yFH1yrRCKBFeLort83QxCfGFVL70NBhhMSMJSM5k
         o2z3vaUs5NoEITZxxCu/o88UIPyOvUn5y/oX0aaP2JZ2ZhpBD0aPEcdxQy9EBmSdTl+g
         S8UlH3QAUyFH+gveKHMXpyZLzWF2Xr8/+xYrtUJR4cTJTlBrHlsNnwDM2y+U13JwbVV9
         PcbQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW+k09US+Lp/x6RqqOlt87ZVY8DDJI/Tz/0kHuZCxi8/k3AmJCfLiwaQqEfB1IIehS2ti1DkA==@lfdr.de
X-Gm-Message-State: AOJu0YzhR+d7ipSK6HQw/Bri4SKF9UitnBpX/M6HXJ5xnONmNkigoFSF
	URgjf7YA6FgF28a5ZhKJ6OjBVg+4Rfgg5QcIXGaJFAS3Ib0jRQr3IKSS
X-Google-Smtp-Source: AGHT+IFHBYlSIn1KXdk3hfLA7kDdNTqEGuSuv5U8+vEjDGuXn/TxZw4dSZchfFy1WFbxvwpNae7FtA==
X-Received: by 2002:a05:6214:2589:b0:72b:ae6b:159e with SMTP id 6a1803df08f44-73941dde6d4mr158675246d6.54.1757472239455;
        Tue, 09 Sep 2025 19:43:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd45tlp6q9pUoXuiSWqh5JVI2BQbczuE58ivasnhhkCXsA==
Received: by 2002:ad4:5f8c:0:b0:72b:8970:ee1 with SMTP id 6a1803df08f44-72d3ba7784cls76248586d6.1.-pod-prod-05-us;
 Tue, 09 Sep 2025 19:43:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX1aGvSFOdxo6hByau8Fn5Z+jJmrh6iH2DOrQ3qO+SN/jOLAuLyuJRUozOgEaV2IwmXP0zdIUn/3rs=@googlegroups.com
X-Received: by 2002:a05:6214:43c9:b0:740:b1c6:d8a0 with SMTP id 6a1803df08f44-740b1c6da23mr126320606d6.18.1757472238677;
        Tue, 09 Sep 2025 19:43:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757472238; cv=none;
        d=google.com; s=arc-20240605;
        b=DKuvXH9hUZeXbnf28jHdEMzjgGksMUXACGWRqGdMyxFBiuvOedwAsKvXkM28ozzETF
         jrzFdfjoo1EdvvQ0W3WfacmNRUqb4yET6HLZEyewmA/CjQPw3aPPCN3D9LU719CaeJ1R
         uQzoByFWwXGQjhwwTrPfhGwsGDVXTdvm+0X2xZCTxJPcAGMjsLYi6liqyBC6BD/HlAOy
         3PnPCXNzdOUI7EJxtEYuGcUsmIkgW+snV7OY/EAoPEHrNP9oPm447o+rQsVYbuDrYsBR
         SmN0xKtC+df92vtSmQKJKZIlRcbdWdGm+V2EEMjBH5hUk+AovNGg15y7/yBt5u98LAC5
         V74Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0koFSnJrv2UowuMhMeqtiJIslvN7BbZv6mHXQ/mKo7A=;
        fh=xWn7BSwXY+xaGscqdMwYHQwh1SvemF1zIxA+wxTk3U4=;
        b=jN9Q7/rF3n18TBf0cVcH0yWGv98SruS3HWq8uSwfO5+9TGhIS8b4aJCMQZSbKp69T7
         jfa1PxZXjnP2Z/gKaWYdjS6+sZoSa6UaDLZKDMhYxIAr0DTHBOT9K4WW26pvfujINkGq
         h1If0EyB7wjX6Z2HSF+t9Mql8AV7I4lTjS7k1fnQjDEuwvAn06jYjw4nLZOcFTiW/hWb
         pC37ciW0UkyfbC8U+2gnxwrnKHGrk6Wjgv/i8Av6mQPEGhH2pF4CnICcWtYer8fI+AKi
         TQoGA2AbJOdThHsa63DPAGYhhOv57xKB9r3CmgdZSGkUidNOCf8ZCkuTAoXzbBVeqlfu
         URpA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CD5Eofcu;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-75ededf0902si54906d6.2.2025.09.09.19.43.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 19:43:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id d2e1a72fcca58-77269d19280so5796854b3a.3
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 19:43:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXESIt0xD00m5QPnayrAZiHFDiIuZiKPua49qe7ujTh/jHfMWb0+0PHFUuFBhlnyccR620pUS2zl54=@googlegroups.com
X-Gm-Gg: ASbGncu3p7F5Ems7wab067njpKfC2pT9EjzFXtpMbzdcQ4S5Rs4vub4N8v+DeCEeRcv
	4oL44Hkb5ERnDc079fSBEZlf8OCXKuZols73kCyfa8AAyMYnt0BSp/0ZxF/vH30mWUkWJUy1Z3x
	oa2wHeNnayyRQ3ldTxqaOD92DHfFtmdU8m19AidENycN7LHBvyPCbZpaaZ0NfKjLw9vcr0m/7Sv
	skr7vistN2L20DHonLL0W5Vl2++TyaHY10IDZr/RHjZXZXMCwdpkSYn+Dfhq6IpVgrFS6TCcNOm
	oJZ5OL4AejknOCoE9nxnys9Fy81Njgpif30VFqN+umPhxetfaCvCcmkCw+7ozOGhx9UX84Wr/Qa
	q0/vJJkwwvc5G27dQpIBSiU8NHhHDXLx7oxZe
X-Received: by 2002:aa7:888a:0:b0:771:ef50:346 with SMTP id d2e1a72fcca58-7742ddf06dcmr17391894b3a.15.1757472238110;
        Tue, 09 Sep 2025 19:43:58 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-774660e58e6sm3514669b3a.12.2025.09.09.19.43.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 19:43:56 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id 3876D41FA3A5; Wed, 10 Sep 2025 09:43:52 +0700 (WIB)
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
Subject: [PATCH v2 03/13] Documentation: perf-security: Convert security credentials bibliography link
Date: Wed, 10 Sep 2025 09:43:18 +0700
Message-ID: <20250910024328.17911-4-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20250910024328.17911-1-bagasdotme@gmail.com>
References: <20250910024328.17911-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1135; i=bagasdotme@gmail.com; h=from:subject; bh=OYt2QegR/+u0q3CRKm7Zg38q7SY9D/3L6tdzv43Jflg=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkHnijWLH+uxHuD5TvzhcJo65MVRz8evf+ht/Kg8H3eu d3xR8redZSyMIhxMciKKbJMSuRrOr3LSORC+1pHmDmsTCBDGLg4BWAiXd8Y/pkdXvTh5u5HL7eU z3No81zweEv6gxSt+G/HWyxWsM1N7zjH8E/xHeNT5tNsutFpemIVy+M+5pasa5QSXynjZOFf2v3 OnBkA
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=CD5Eofcu;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::432
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

Use internal cross-reference for bibliography link to security
credentials docs.

Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 Documentation/admin-guide/perf-security.rst | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/Documentation/admin-guide/perf-security.rst b/Documentation/admin-guide/perf-security.rst
index 34aa334320cad3..ec308e00771427 100644
--- a/Documentation/admin-guide/perf-security.rst
+++ b/Documentation/admin-guide/perf-security.rst
@@ -311,7 +311,7 @@ Bibliography
 .. [2] `<http://man7.org/linux/man-pages/man2/perf_event_open.2.html>`_
 .. [3] `<http://web.eece.maine.edu/~vweaver/projects/perf_events/>`_
 .. [4] `<https://perf.wiki.kernel.org/index.php/Main_Page>`_
-.. [5] `<https://www.kernel.org/doc/html/latest/security/credentials.html>`_
+.. [5] Documentation/security/credentials.rst
 .. [6] `<http://man7.org/linux/man-pages/man7/capabilities.7.html>`_
 .. [7] `<http://man7.org/linux/man-pages/man2/ptrace.2.html>`_
 .. [8] `<https://en.wikipedia.org/wiki/Hardware_performance_counter>`_
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910024328.17911-4-bagasdotme%40gmail.com.
