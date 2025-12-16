Return-Path: <kasan-dev+bncBDPZFQ463EFRBNXRQXFAMGQEMHNMLAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8BA21CC3E06
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 16:20:24 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-4ed74ab4172sf100479091cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 07:20:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765898423; cv=pass;
        d=google.com; s=arc-20240605;
        b=M/BaGY/en0GOoHrLjrVB7mOi3VxsoQMJIujajxKZr+RKedUc7XIxYJ/NaomiGHONCL
         LTlvjvM5VG6Q3BAJ704pJ7Cpd06BjBhyVBRG6Y5d5btf9uphpgK4RWQ+h5UQT8UABigo
         YZNG/ts4eGNeXHz+fdJc7JR85wpjVsTolGjSIT2Pc53ynmv+4+3QtizbFIUi16vueD0+
         WW9d+b6I52uYTSF38Oj+cE3MldX6m/PwvOTnHaQ/2ccMDxt9zD6bn4KWt7B0fhgjIC8K
         GOul7IB4+Kp2CfzhnLYM44kBhxhaD6UI18TaSuUyx2UfJW1UXVPPtGCrkJ75wCeLEkOv
         77ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=7Q2ffGD/UCid0OsXbphq0tuizfvMYvZch+UWKzRI00o=;
        fh=LHuVg2cRSZfWC8ttCUuMh7IqGfrTgFO5XdcKY4zVb58=;
        b=XnkRoENyhH+LEyUafEE4DfyfOWBhptJfKM45Rq3+ubcKT3YdH9hqQy9sQe0E4bBQlx
         bKZnLcz1dVPDB0BSRSklP1b03mRvyjgb8dDqdv9QFYheD8imN17pBQzP49UzEz+exajA
         NhRg+C12Dx4G+o4uRRJFFPdvMul7TrungiuwlkH8p1PN/2QJVFGvX2t4MHla9CyVMyDr
         /3eHFs8DKACnUzhcgRjqbTGVBL1nE8pefF2ExTWB29hZHQDqlsMC/ylWNL5CGmA2k45Q
         44giqb1EV8TWxjn9TdsYytsJd1n0bOufISwFLY5utAobTpQUaSkqXCDLlYnl6aVXAPTZ
         cZ2A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dqDMgaFd;
       spf=pass (google.com: domain of alexdeucher@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=alexdeucher@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765898423; x=1766503223; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7Q2ffGD/UCid0OsXbphq0tuizfvMYvZch+UWKzRI00o=;
        b=JIbSrn9r8VhYUHqcteLq1HtIb5/PFBKdLWA5FOoiFPjopqToMCpR2MiOdHrYoB1de8
         4oLnRiiyFhGLt1412LSDQRrc4BRfE0PEZC2Cq4A/gattl//kBAVfdpIpabfNtRR8eEXe
         FZ1+2SfK2/LVBgqK9AF6JLCW0RIw5ErBu2Vrs9r6WPgadDILztok8Y6xO01LDqW+MfH6
         TM6awcA04sV7tePoytzl+ff9ChTZigO6bP3zm7WdpjFJXkjzy8jkHXAJpVmRd3K7kKyF
         XY21OehToarnGtj+VT9L1gatn/oFziKkiJnvQUvf/mxjVxyk3xSzooEnTzlKbzd+CRKj
         zZOQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1765898423; x=1766503223; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7Q2ffGD/UCid0OsXbphq0tuizfvMYvZch+UWKzRI00o=;
        b=K7q3ikbCE8qsNCQAwugqiAjvG08Vk9swWOA+Qh2ZUPE/nlRRWYx/i0YW+v1A7dfnr+
         7L863IFfrEyMfrOWcTYtZbvyPEsizcRceDYisXlbC+5iaTJ+PwCWd7pRkvm7z8HZIpkN
         Tu4C3pZt0JlnPm76CRQbE+cuz6475FDAhi3tIpOemXopIg+cnPtHI66Sy3QN8FYRU44o
         d9zIYAeoZH8ECmfXcbXgz3ZFo2rGasQze3l6j7R17cV9WWldlRomWIgdU80JmdioNvSp
         /pI3gHtZDPA/hOtmlMWBxcHwjcWGZ1V7Dro6gVP1nZ9zkGAdaKP/JGrDBOQkemq5jnAO
         czTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765898423; x=1766503223;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7Q2ffGD/UCid0OsXbphq0tuizfvMYvZch+UWKzRI00o=;
        b=M6LWPG2a6NdstFKuezQ2afu/pySvrDWvDWllYn00feHuK22SzjEkaugQQ3fBrqpE7P
         8kQ16VsGH04LAFS5U222S4HCq8mFfyOO9+SMuqLrBdVypOv90HQEEd+l0Pu2HDfyaun2
         FPaAWgz4cpENNzu1XV6Bh7P/IV5hk16IYYG+SZlEUKxy9FCaExCflTYaH6DByXeAMMw9
         M0tx+a+6XiJm1yMyunk8679WYRwUjEMrtVGolMu6g2XdHMlYEhHI7K04JMYCbt1VswmI
         CmZrz7W2+qEx0BhbcrJ0Z1lZp8JNpvf0cjyjAFdNziDjUv0rM2m0+BR/9b6T2+xL99iV
         cXSw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUuhnA6gnBc3rjv6HJflSbaFDAUJxBJ3yVqTvnAtxiqCb1LzbzSlWNsal09jt9GZYZL1Rms4w==@lfdr.de
X-Gm-Message-State: AOJu0Yy29mN6/nKsw+svHLD20aWqE6t92rXa1XPsu5OahpkrSxTFn3gj
	jJf6SucxXfsT43uUbDKvqmXMceaIP2hqfm0fc4XUJ/DXLGiISl+lp/AU
X-Google-Smtp-Source: AGHT+IH3egOoOZI/4YoL8PMk810sHZdJpV4ZLOutJeNH4/4v2YcAqk4wwKOiudtWCmm1dKAB3KsVfg==
X-Received: by 2002:ac8:7f42:0:b0:4f1:83e4:7247 with SMTP id d75a77b69052e-4f1d05db49bmr225523731cf.60.1765898422828;
        Tue, 16 Dec 2025 07:20:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWY8AQVKxi8f5WWM3xe/F1w6vbN8LY+ET6loW7rCAb4nMQ=="
Received: by 2002:a05:6214:3018:b0:779:d180:7e3f with SMTP id
 6a1803df08f44-8887cd8fedels85395186d6.1.-pod-prod-01-us; Tue, 16 Dec 2025
 07:20:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUOwOLPZph70GQIGX7UOFWlUYUHLLgQDjR1VUoqfLnuTB1XWqMBfW/lPIcudzURJcTH4Cob/hCziqA=@googlegroups.com
X-Received: by 2002:a05:6214:3187:b0:880:4bb9:4c99 with SMTP id 6a1803df08f44-88880206493mr205988566d6.66.1765898421706;
        Tue, 16 Dec 2025 07:20:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765898421; cv=none;
        d=google.com; s=arc-20240605;
        b=PXO/ockle6B0mi/936MOWJMo29QWPdUvi4ks7iIh0m2+4i8NSM0zNr40vrPil0nBv/
         PjU5hcH8IuLs1fyoUxCXfMUljUqePNKUIs8X6tzqXYIf7ZGiQcUR7oNuDe6zK2z7FSMZ
         UWr6rCMtT0LAK/Ywll7+Vk7eqxKKLNwjNO/QFhkYx+rr+lJC5TjayRQ++V75X9tHbrH9
         PdHUv0kVyd0o5ovUq8QGvqtCTStElwISHh6AjCJgjLNGMj03zvvuVrCS4W6/GV3cCIwL
         yTsLgjkoRnBIKOXjLXQqGHF5k+1fsF+txIlY9ewdJ45+zCpBr2CUWT07ZO12SfuTFdPZ
         l/qA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Um9j1NvhAvuOmXHqodLfor6UadH2pWBjGMeLJlrrYrA=;
        fh=aynWn6s13n2GUjVwoSBwiMxiohv0ZbCdAqLKi+knWMg=;
        b=H02UtS/JPj+1EuqtGnCgyYPaJaAMMwF/cqXwjQsmGdiIMI58LfU7Id+iBqjjkT0zlS
         Sd5qaYS1Ppt2b5h+LNI9sdO6x1rjMghDc2a5Nj5PxXJ5/jsgQGfE02zYCGu1Th5KDiAs
         1AVvmT26diWzhYr2XgXPa8qw0HSYOTjLFSrenTpMlZQM0ndD8X8AmjHP29Atw8xOE6s3
         PmG4tup064wS1zVmH1O+eAtW+ozmnjJ4ejT/BF6F3RjzR4cd5SVp85JXmyVbuGhipvRa
         9PIOdlmALQUVv01F2RFUFkN1cWbCftJS22QJmxjeKQQWLA8kO0cG5dsdxlglkzyyaOFN
         9w5A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dqDMgaFd;
       spf=pass (google.com: domain of alexdeucher@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=alexdeucher@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62f.google.com (mail-pl1-x62f.google.com. [2607:f8b0:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-88987f2cd69si4760786d6.0.2025.12.16.07.20.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Dec 2025 07:20:21 -0800 (PST)
Received-SPF: pass (google.com: domain of alexdeucher@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) client-ip=2607:f8b0:4864:20::62f;
Received: by mail-pl1-x62f.google.com with SMTP id d9443c01a7336-2a08c65fceeso5973405ad.2
        for <kasan-dev@googlegroups.com>; Tue, 16 Dec 2025 07:20:21 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV/6p/8SBw6QUGBt2BwGmh/nSULBzpNM+sCNrcfU1Xos8ww9ui64h/eocz4NQ/euw6GiIuiqZaovTI=@googlegroups.com
X-Gm-Gg: AY/fxX4ZZrzbbUaS0mV0K7WWETNCNEUI0iI+NvR65M0W0GWG1suC2rJ7osCwrl3shSS
	NRlEqHIx/c/g3GCSBuDkl8t1ttoJkxLkl35/ZYIv4x3kPcPfHibrroXO7KtQ7J1/J3VJ6/PQCWr
	wC69eEhQUiG4lmM8b3wj+HeMxQgpjIC0vm7XVjgN1BgeZhcnSCFm+LrgZKvHXBRmjdasNROb17q
	bJaeUH6srUwCtumoBrT/GPqFcnS0/3mfp6EyTsDdJIeYGFGnU2+zB/rN3DvS45FRIwUvpj6GLFv
	Gudnwhs=
X-Received: by 2002:a05:7022:3a0d:b0:11e:3e9:3ea4 with SMTP id
 a92af1059eb24-11f34c52cc5mr5906109c88.6.1765898419103; Tue, 16 Dec 2025
 07:20:19 -0800 (PST)
MIME-Version: 1.0
References: <20251215113903.46555-1-bagasdotme@gmail.com> <20251215113903.46555-11-bagasdotme@gmail.com>
In-Reply-To: <20251215113903.46555-11-bagasdotme@gmail.com>
From: Alex Deucher <alexdeucher@gmail.com>
Date: Tue, 16 Dec 2025 10:20:06 -0500
X-Gm-Features: AQt7F2ra4W4DJMCA0k4t80_q2saRqZRxc2HY97wTRTVoyOkAEkAv1EtqbtLiuMo
Message-ID: <CADnq5_P04522xETHty9hn5JO=mNbKSg3Pa68=u8cZ+JgNLt1Jg@mail.gmail.com>
Subject: Re: [PATCH 10/14] drm/amdgpu: Describe @AMD_IP_BLOCK_TYPE_RAS in
 amd_ip_block_type enum
To: Bagas Sanjaya <bagasdotme@gmail.com>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	Linux AMDGPU <amd-gfx@lists.freedesktop.org>, 
	Linux DRI Development <dri-devel@lists.freedesktop.org>, 
	Linux Filesystems Development <linux-fsdevel@vger.kernel.org>, Linux Media <linux-media@vger.kernel.org>, 
	linaro-mm-sig@lists.linaro.org, kasan-dev@googlegroups.com, 
	Linux Virtualization <virtualization@lists.linux.dev>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux Network Bridge <bridge@lists.linux.dev>, 
	Linux Networking <netdev@vger.kernel.org>, Harry Wentland <harry.wentland@amd.com>, 
	Leo Li <sunpeng.li@amd.com>, Rodrigo Siqueira <siqueira@igalia.com>, 
	Alex Deucher <alexander.deucher@amd.com>, =?UTF-8?Q?Christian_K=C3=B6nig?= <christian.koenig@amd.com>, 
	David Airlie <airlied@gmail.com>, Simona Vetter <simona@ffwll.ch>, 
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>, Maxime Ripard <mripard@kernel.org>, 
	Thomas Zimmermann <tzimmermann@suse.de>, Matthew Brost <matthew.brost@intel.com>, 
	Danilo Krummrich <dakr@kernel.org>, Philipp Stanner <phasta@kernel.org>, 
	Alexander Viro <viro@zeniv.linux.org.uk>, Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>, 
	Sumit Semwal <sumit.semwal@linaro.org>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Jason Wang <jasowang@redhat.com>, 
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>, =?UTF-8?Q?Eugenio_P=C3=A9rez?= <eperezma@redhat.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, 
	Nikolay Aleksandrov <razor@blackwall.org>, Ido Schimmel <idosch@nvidia.com>, 
	"David S. Miller" <davem@davemloft.net>, Eric Dumazet <edumazet@google.com>, 
	Jakub Kicinski <kuba@kernel.org>, Paolo Abeni <pabeni@redhat.com>, Simon Horman <horms@kernel.org>, 
	Taimur Hassan <Syed.Hassan@amd.com>, Wayne Lin <Wayne.Lin@amd.com>, Alex Hung <alex.hung@amd.com>, 
	Aurabindo Pillai <aurabindo.pillai@amd.com>, Dillon Varone <Dillon.Varone@amd.com>, 
	George Shen <george.shen@amd.com>, Aric Cyr <aric.cyr@amd.com>, 
	Cruise Hung <Cruise.Hung@amd.com>, Mario Limonciello <mario.limonciello@amd.com>, 
	Sunil Khatri <sunil.khatri@amd.com>, Dominik Kaszewski <dominik.kaszewski@amd.com>, 
	David Hildenbrand <david@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, Max Kellermann <max.kellermann@ionos.com>, 
	"Nysal Jan K.A." <nysal@linux.ibm.com>, Ryan Roberts <ryan.roberts@arm.com>, 
	Alexey Skidanov <alexey.skidanov@intel.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Kent Overstreet <kent.overstreet@linux.dev>, Vitaly Wool <vitaly.wool@konsulko.se>, 
	Harry Yoo <harry.yoo@oracle.com>, Mateusz Guzik <mjguzik@gmail.com>, NeilBrown <neil@brown.name>, 
	Amir Goldstein <amir73il@gmail.com>, Jeff Layton <jlayton@kernel.org>, 
	Ivan Lipski <ivan.lipski@amd.com>, Tao Zhou <tao.zhou1@amd.com>, 
	YiPeng Chai <YiPeng.Chai@amd.com>, Hawking Zhang <Hawking.Zhang@amd.com>, 
	Lyude Paul <lyude@redhat.com>, Daniel Almeida <daniel.almeida@collabora.com>, 
	Luben Tuikov <luben.tuikov@amd.com>, Matthew Auld <matthew.auld@intel.com>, 
	Roopa Prabhu <roopa@cumulusnetworks.com>, Mao Zhu <zhumao001@208suo.com>, 
	Shaomin Deng <dengshaomin@cdjrlc.com>, Charles Han <hanchunchao@inspur.com>, 
	Jilin Yuan <yuanjilin@cdjrlc.com>, Swaraj Gaikwad <swarajgaikwad1925@gmail.com>, 
	George Anthony Vernon <contact@gvernon.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexdeucher@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=dqDMgaFd;       spf=pass
 (google.com: domain of alexdeucher@gmail.com designates 2607:f8b0:4864:20::62f
 as permitted sender) smtp.mailfrom=alexdeucher@gmail.com;       dmarc=pass
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

On Mon, Dec 15, 2025 at 6:48=E2=80=AFAM Bagas Sanjaya <bagasdotme@gmail.com=
> wrote:
>
> Sphinx reports kernel-doc warning:
>
> WARNING: ./drivers/gpu/drm/amd/include/amd_shared.h:113 Enum value 'AMD_I=
P_BLOCK_TYPE_RAS' not described in enum 'amd_ip_block_type'
>
> Describe the value to fix it.
>
> Fixes: 7169e706c82d7b ("drm/amdgpu: Add ras module ip block to amdgpu dis=
covery")
> Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
> ---
>  drivers/gpu/drm/amd/include/amd_shared.h | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/drivers/gpu/drm/amd/include/amd_shared.h b/drivers/gpu/drm/a=
md/include/amd_shared.h
> index 17945094a13834..d8ed3799649172 100644
> --- a/drivers/gpu/drm/amd/include/amd_shared.h
> +++ b/drivers/gpu/drm/amd/include/amd_shared.h
> @@ -89,6 +89,7 @@ enum amd_apu_flags {
>  * @AMD_IP_BLOCK_TYPE_VPE: Video Processing Engine
>  * @AMD_IP_BLOCK_TYPE_UMSCH_MM: User Mode Scheduler for Multimedia
>  * @AMD_IP_BLOCK_TYPE_ISP: Image Signal Processor
> +* @AMD_IP_BLOCK_TYPE_RAS: RAS

Reliability, Availability, Serviceability.  I've fixed this up locally
and applied the patch.

Thanks,

Alex

>  * @AMD_IP_BLOCK_TYPE_NUM: Total number of IP block types
>  */
>  enum amd_ip_block_type {
> --
> An old man doll... just what I always wanted! - Clara
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ADnq5_P04522xETHty9hn5JO%3DmNbKSg3Pa68%3Du8cZ%2BJgNLt1Jg%40mail.gmail.com.
